use std::{
    collections::HashSet,
    ops::DerefMut,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use dashmap::{DashMap, DashSet};
use deadpool_postgres::{Config, GenericClient, ManagerConfig, Pool, RecyclingMethod};
use ethereum_consensus::{
    altair::Hash32, primitives::BlsPublicKey, ssz::prelude::ByteVector,
    types::mainnet::ExecutionPayload,
};

use helix_common::{
    api::{
        builder_api::BuilderGetValidatorsResponseEntry, data_api::BidFilters,
        proposer_api::ValidatorRegistrationInfo,
    },
    bid_submission::{BidTrace, SignedBidSubmission},
    simulator::BlockSimError,
    BuilderInfo, GetPayloadTrace, PostgresConfig, RelayConfig, SignedValidatorRegistrationEntry,
    SubmissionTrace, ValidatorSummary,
};
use tokio_postgres::{types::ToSql, NoTls};
use tracing::{error, info};

use crate::{
    error::DatabaseError,
    postgres::{
        postgres_db_filters::PgBidFilters,
        postgres_db_init::run_migrations_async,
        postgres_db_row_parsing::{parse_bytes_to_pubkey, parse_row, parse_rows},
        postgres_db_u256_parsing::PostgresNumeric,
    },
    types::{BidSubmissionDocument, BuilderInfoDocument, DeliveredPayloadDocument},
    DatabaseService,
};

#[derive(Clone)]
pub struct PostgresDatabaseService {
    validator_registration_cache: Arc<DashMap<BlsPublicKey, SignedValidatorRegistrationEntry>>,
    pending_validator_registrations: Arc<DashSet<BlsPublicKey>>,
    known_validators_cache: Arc<DashSet<BlsPublicKey>>,
    region: i16,
    pool: Arc<Pool>,
}

impl PostgresDatabaseService {
    pub fn new(cfg: &Config, region: i16) -> Result<Self, Box<dyn std::error::Error>> {
        let pool = cfg.create_pool(None, NoTls)?;
        Ok(PostgresDatabaseService {
            validator_registration_cache: Arc::new(DashMap::new()),
            pending_validator_registrations: Arc::new(DashSet::new()),
            known_validators_cache: Arc::new(DashSet::new()),
            region,
            pool: Arc::new(pool),
        })
    }

    pub fn from_relay_config(
        relay_config: &RelayConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut cfg = Config::new();
        cfg.host = Some(relay_config.postgres.hostname.clone());
        cfg.port = Some(5432);
        cfg.dbname = Some(relay_config.postgres.db_name.clone());
        cfg.user = Some(relay_config.postgres.user.clone());
        cfg.password = Some(relay_config.postgres.password.clone());
        cfg.manager = Some(ManagerConfig { recycling_method: RecyclingMethod::Fast });
        let pool = cfg.create_pool(None, NoTls)?;
        Ok(PostgresDatabaseService {
            validator_registration_cache: Arc::new(DashMap::new()),
            pending_validator_registrations: Arc::new(DashSet::new()),
            known_validators_cache: Arc::new(DashSet::new()),
            region: relay_config.postgres.region,
            pool: Arc::new(pool),
        })
    }

    pub async fn run_migrations(&self) {
        let mut conn = self.pool.get().await.unwrap();
        let client = conn.deref_mut().deref_mut();
        match run_migrations_async(client).await {
            Ok(report) => {
                info!("Applied migrations: {}", report.applied_migrations().len());
                info!("Migrations: {:?}", report);
            }
            Err(e) => {
                panic!("Error applying migrations: {}", e);
            }
        };
    }

    pub async fn init_region(&self, config: &RelayConfig) {
        let client = self.pool.get().await.unwrap();
        match client
            .execute(
                "
                INSERT INTO region (id, name)
                VALUES ($1, $2)
                ON CONFLICT (id)
                DO NOTHING
            ",
                &[&(config.postgres.region), &(config.postgres.region_name)],
            )
            .await
        {
            Ok(_) => {
                info!("Region {} initialized", config.postgres.region);
            }
            Err(e) => {
                panic!("Error initializing region {}: {}", config.postgres.region, e);
            }
        };
    }

    pub async fn start_registration_processor(&self) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        let self_clone = self.clone();
        tokio::spawn(async move {
            loop {
                interval.tick().await;
                match self_clone.pending_validator_registrations.len() {
                    0 => continue,
                    _ => {
                        let mut entries = Vec::new();
                        for key in self_clone.pending_validator_registrations.iter() {
                            if let Some(entry) = self_clone.validator_registration_cache.get(&*key)
                            {
                                entries.push(entry.registration_info.clone());
                            }
                        }
                        match self_clone._save_validator_registrations(entries).await {
                            Ok(_) => {
                                self_clone.pending_validator_registrations.clear();
                                info!("Saved validator registrations");
                            }
                            Err(e) => {
                                error!("Error saving validator registrations: {}", e);
                            }
                        };
                    }
                };
            }
        });
    }

    async fn _save_validator_registrations(
        &self,
        mut entries: Vec<ValidatorRegistrationInfo>,
    ) -> Result<(), DatabaseError> {
        let mut client = self.pool.get().await?;

        let batch_size = 1000;
        for chunk in entries.chunks(batch_size) {
            let transaction = client.transaction().await?;

            let mut structured_params_for_reg: Vec<(&[u8], i32, i64, &[u8], &[u8], SystemTime)> =
                Vec::with_capacity(chunk.len());
            let mut structured_params_for_pref: Vec<(&[u8], bool)> =
                Vec::with_capacity(chunk.len());

            for entry in chunk.iter() {
                let registration = &entry.registration.message;
                let fee_recipient = &registration.fee_recipient;
                let public_key = &registration.public_key;
                let signature = &entry.registration.signature;

                let inserted_at = SystemTime::now();

                // Collect the parameters in a structured manner
                structured_params_for_reg.push((
                    fee_recipient.as_ref(),
                    registration.gas_limit as i32,
                    registration.timestamp as i64,
                    public_key.as_ref(),
                    signature.as_ref(),
                    inserted_at,
                ));

                structured_params_for_pref.push((public_key.as_ref(), entry.preferences.censoring));
            }

            // Prepare the params vector from the structured parameters
            let params: Vec<&(dyn ToSql + Sync)> = structured_params_for_reg
                .iter()
                .flat_map(|tuple| {
                    vec![
                        &tuple.0,
                        &tuple.1 as &(dyn ToSql + Sync),
                        &tuple.2,
                        &tuple.3,
                        &tuple.4,
                        &tuple.5,
                    ]
                })
                .collect();

            // Construct the SQL statement with multiple VALUES clauses
            let mut sql = String::from("INSERT INTO validator_registrations (fee_recipient, gas_limit, timestamp, public_key, signature, inserted_at) VALUES ");
            let values_clauses: Vec<String> = params
                .chunks(6)
                .enumerate()
                .map(|(i, _)| {
                    if i == 0 {
                        String::from("($1, $2, $3, $4, $5, $6)")
                    } else {
                        let offset = i * 6;
                        format!(
                            "(${}, ${}, ${}, ${}, ${}, ${})",
                            offset + 1,
                            offset + 2,
                            offset + 3,
                            offset + 4,
                            offset + 5,
                            offset + 6,
                        )
                    }
                })
                .collect();

            // Join the values clauses and append them to the SQL statement
            sql.push_str(&values_clauses.join(", "));
            sql.push_str(" ON CONFLICT (public_key) DO UPDATE SET fee_recipient = excluded.fee_recipient, gas_limit = excluded.gas_limit, timestamp = excluded.timestamp, signature = excluded.signature, inserted_at = excluded.inserted_at");

            // Execute the query
            transaction.execute(&sql, &params[..]).await?;

            let params: Vec<&(dyn ToSql + Sync)> = structured_params_for_pref
                .iter()
                .flat_map(|tuple| vec![&tuple.0 as &(dyn ToSql + Sync), &tuple.1])
                .collect();

            // Construct the SQL statement with multiple VALUES clauses
            let mut sql =
                String::from("INSERT INTO validator_preferences (public_key, censoring) VALUES ");
            let values_clauses: Vec<String> = params
                .chunks(2)
                .enumerate()
                .map(|(i, _)| {
                    if i == 0 {
                        String::from("($1, $2)")
                    } else {
                        let offset = i * 2;
                        format!("(${}, ${})", offset + 1, offset + 2,)
                    }
                })
                .collect();

            // Join the values clauses and append them to the SQL statement
            sql.push_str(&values_clauses.join(", "));
            sql.push_str(" ON CONFLICT (public_key) DO UPDATE SET censoring = excluded.censoring");

            // Execute the query
            transaction.execute(&sql, &params[..]).await?;

            transaction.commit().await?;
        }

        Ok(())
    }
}

impl Default for PostgresDatabaseService {
    fn default() -> Self {
        let mut cfg = Config::new();
        cfg.host = Some("localhost".to_string());
        cfg.port = Some(5432);
        cfg.dbname = Some("postgres".to_string());
        cfg.user = Some("postgres".to_string());
        cfg.password = Some("password".to_string());
        cfg.manager = Some(ManagerConfig { recycling_method: RecyclingMethod::Fast });

        let pool = cfg.create_pool(None, NoTls).unwrap();

        PostgresDatabaseService {
            validator_registration_cache: Arc::new(DashMap::new()),
            pending_validator_registrations: Arc::new(DashSet::new()),
            known_validators_cache: Arc::new(DashSet::new()),
            region: 0,
            pool: Arc::new(pool),
        }
    }
}

#[async_trait]
impl DatabaseService for PostgresDatabaseService {
    async fn save_validator_registration(
        &self,
        registration_info: ValidatorRegistrationInfo,
    ) -> Result<(), DatabaseError> {
        let registration = registration_info.registration.message.clone();

        if let Some(entry) = self.validator_registration_cache.get(&registration.public_key) {
            if entry.registration_info.registration.message.timestamp >= registration.timestamp {
                return Ok(());
            }
        }

        let fee_recipient = &registration.fee_recipient;
        let public_key = &registration.public_key;
        let signature = &registration_info.registration.signature;

        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        let inserted_at = SystemTime::now();

        transaction
            .execute(
                "INSERT INTO validator_preferences (public_key, censoring)
            VALUES ($1, $2)
            ON CONFLICT (public_key)
            DO UPDATE SET
                censoring = excluded.censoring
            ",
                &[&public_key.as_ref(), &registration_info.preferences.censoring],
            )
            .await?;

        match transaction.execute(
            "
                INSERT INTO validator_registrations (fee_recipient, gas_limit, timestamp, public_key, signature, inserted_at)
                VALUES ($1, $2, $3, $4, $5,$6)
                ON CONFLICT (public_key)
                DO UPDATE SET
                    fee_recipient = excluded.fee_recipient,
                    gas_limit = excluded.gas_limit,
                    timestamp = excluded.timestamp,
                    signature = excluded.signature,
                    inserted_at = excluded.inserted_at
            ",
            &[
                &(fee_recipient.as_ref()),
                &(registration.gas_limit as i32),
                &(registration.timestamp as i64),
                &(public_key.as_ref()),
                &(signature.as_ref()),
                &(inserted_at)],
        ).await {
            Ok(_) => {
                self.validator_registration_cache.insert(public_key.clone(), SignedValidatorRegistrationEntry {
                    registration_info,
                    inserted_at: inserted_at.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                });
            }
            Err(e) => {
                return Err(DatabaseError::from(e))
            },
        };

        transaction.commit().await?;

        Ok(())
    }

    async fn save_validator_registrations(
        &self,
        mut entries: Vec<ValidatorRegistrationInfo>,
    ) -> Result<(), DatabaseError> {
        entries.retain(|entry| {
            if let Some(existing_entry) =
                self.validator_registration_cache.get(&entry.registration.message.public_key)
            {
                if existing_entry.registration_info.registration.message.timestamp
                    >= entry.registration.message.timestamp
                {
                    return false;
                }
            }
            true
        });

        for entry in entries.iter() {
            self.pending_validator_registrations
                .insert(entry.registration.message.public_key.clone());
            self.validator_registration_cache.insert(
                entry.registration.message.public_key.clone(),
                SignedValidatorRegistrationEntry::new(entry.clone()),
            );
        }

        Ok(())
    }

    async fn get_validator_registration(
        &self,
        pub_key: BlsPublicKey,
    ) -> Result<SignedValidatorRegistrationEntry, DatabaseError> {
        match self
            .pool
            .get()
            .await?
            .query(
                "
                SELECT
                    validator_registrations.fee_recipient,
                    validator_registrations.gas_limit,
                    validator_registrations.timestamp,
                    validator_registrations.public_key,
                    validator_registrations.signature,
                    validator_preferences.censoring,
                    validator_registrations.inserted_at
                FROM validator_registrations
                INNER JOIN validator_preferences ON validator_registrations.public_key = validator_preferences.public_key
                WHERE validator_registrations.public_key = $1
            ",
                &[&(pub_key.as_ref())],
            )
            .await?
        {
            rows if rows.is_empty() => Err(DatabaseError::ValidatorRegistrationNotFound),
            rows => parse_row(rows.get(0).unwrap()),
        }
    }

    async fn get_validator_registrations_for_pub_keys(
        &self,
        pub_keys: Vec<BlsPublicKey>,
    ) -> Result<Vec<SignedValidatorRegistrationEntry>, DatabaseError> {
        let client = self.pool.get().await.map_err(DatabaseError::from)?;

        // Constructing the query
        let placeholders: Vec<String> = (1..=pub_keys.len()).map(|i| format!("${}", i)).collect();
        let query = format!(
            "SELECT *
            FROM validator_registrations
            INNER JOIN validator_preferences ON validator_registrations.public_key = validator_preferences.public_key
            WHERE validator_preferences.public_key IN ({})",
            placeholders.join(", ")
        );

        // Preparing the query
        let stmt = client.prepare(&query).await.map_err(DatabaseError::from)?;

        let params: Vec<Box<dyn ToSql + Sync + Send>> = pub_keys
            .iter()
            .map(|key| Box::new(key.as_ref()) as Box<dyn ToSql + Sync + Send>)
            .collect();

        let params_slice: Vec<&(dyn ToSql + Sync)> =
            params.iter().map(|b| b.as_ref() as &(dyn ToSql + Sync)).collect();

        parse_rows(client.query(&stmt, &params_slice).await.map_err(DatabaseError::from)?)
    }

    async fn get_validator_registration_timestamp(
        &self,
        pub_key: BlsPublicKey,
    ) -> Result<u64, DatabaseError> {
        self.get_validator_registration(pub_key).await.map(|entry| entry.inserted_at)
    }

    async fn set_proposer_duties(
        &self,
        proposer_duties: Vec<BuilderGetValidatorsResponseEntry>,
    ) -> Result<(), DatabaseError> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        transaction
            .execute(
                "
                TRUNCATE TABLE proposer_duties;
            ",
                &[],
            )
            .await?;

        let mut structured_params: Vec<(i32, i32, &[u8])> =
            Vec::with_capacity(proposer_duties.len());
        for entry in proposer_duties.iter() {
            structured_params.push((
                entry.slot as i32,
                entry.validator_index as i32,
                entry.entry.registration.message.public_key.as_ref(),
            ));
        }

        // Prepare the params vector from the structured parameters
        let params: Vec<&(dyn ToSql + Sync)> = structured_params
            .iter()
            .flat_map(|tuple| vec![&tuple.0, &tuple.1, &tuple.2 as &(dyn ToSql + Sync)])
            .collect();

        // Construct the SQL statement with multiple VALUES clauses
        let mut sql = String::from(
            "INSERT INTO proposer_duties (slot_number, validator_index, public_key) VALUES ",
        );
        let values_clauses: Vec<String> = params
            .chunks(3)
            .enumerate()
            .map(|(i, _)| {
                if i == 0 {
                    String::from("($1, $2, $3)")
                } else {
                    let offset = i * 3;
                    format!("(${}, ${}, ${})", offset + 1, offset + 2, offset + 3)
                }
            })
            .collect();

        // Join the values clauses and append them to the SQL statement
        sql.push_str(&values_clauses.join(", "));

        // Execute the query
        transaction.execute(&sql, &params[..]).await?;

        transaction.commit().await?;

        Ok(())
    }

    async fn get_proposer_duties(
        &self,
    ) -> Result<Vec<BuilderGetValidatorsResponseEntry>, DatabaseError> {
        parse_rows(
            self.pool
                .get()
                .await?
                .query(
                    "
                            SELECT * FROM proposer_duties
                            INNER JOIN validator_registrations
                            ON proposer_duties.public_key = validator_registrations.public_key
                            INNER JOIN validator_preferences
                            ON proposer_duties.public_key = validator_preferences.public_key
                        ",
                    &[],
                )
                .await?,
        )
    }

    async fn set_known_validators(
        &self,
        known_validators: Vec<ValidatorSummary>,
    ) -> Result<(), DatabaseError> {
        if known_validators.is_empty() {
            return Ok(()); // Early return if there are no validators to process.
        }

        self.known_validators_cache.clear();

        for validator in known_validators.iter() {
            self.known_validators_cache.insert(validator.validator.public_key.clone());
        }

        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        transaction
            .execute(
                "
                TRUNCATE TABLE known_validators;
            ",
                &[],
            )
            .await?;

        let batch_size = 10000;

        for chunk in known_validators.chunks(batch_size) {
            let mut sql = String::from("INSERT INTO known_validators (public_key) VALUES ");
            let values_clauses: Vec<String> =
                chunk.iter().enumerate().map(|(i, _)| format!("(${})", i + 1)).collect();

            sql.push_str(&values_clauses.join(", "));
            sql.push_str(" ON CONFLICT (public_key) DO NOTHING");

            let mut structured_params: Vec<&[u8]> = Vec::new();
            for validator in chunk.iter() {
                structured_params.push(validator.validator.public_key.as_ref());
            }

            let params: Vec<&(dyn ToSql + Sync)> =
                structured_params.iter().flat_map(|v| vec![v as &(dyn ToSql + Sync)]).collect();

            transaction.execute(&sql, &params[..]).await?;
        }

        transaction.commit().await?;

        Ok(())
    }

    async fn check_known_validators(
        &self,
        public_keys: Vec<BlsPublicKey>,
    ) -> Result<HashSet<BlsPublicKey>, DatabaseError> {
        let client = self.pool.get().await?;
        let mut pub_keys = HashSet::new();

        if self.known_validators_cache.is_empty() {
            let rows = client.query("SELECT * FROM known_validators", &[]).await?;
            for row in rows {
                let public_key: BlsPublicKey =
                    parse_bytes_to_pubkey(row.get::<&str, &[u8]>("public_key"))?;
                self.known_validators_cache.insert(public_key.clone());
            }
        }

        for public_key in public_keys.iter() {
            if self.known_validators_cache.contains(public_key) {
                pub_keys.insert(public_key.clone());
            } else {
                let rows = client
                    .query(
                        "SELECT * FROM known_validators WHERE public_key = $1",
                        &[&(public_key.as_ref())],
                    )
                    .await?;
                for row in rows {
                    let public_key: BlsPublicKey =
                        parse_bytes_to_pubkey(row.get::<&str, &[u8]>("public_key"))?;
                    self.known_validators_cache.insert(public_key.clone());
                }
            }
        }

        Ok(pub_keys)
    }

    async fn save_too_late_get_payload(
        &self,
        slot: u64,
        proposer_pub_key: &BlsPublicKey,
        payload_hash: &Hash32,
        message_received: u64,
        payload_fetched: u64,
    ) -> Result<(), DatabaseError> {
        let region_id = self.region;
        self.pool
            .get()
            .await?
            .execute(
                "
                    INSERT INTO late_payload
                        (block_hash, slot_number, region_id, proposer_pubkey, message_received, payload_fetched)
                    VALUES 
                        ($1, $2, $3, $4, $5, $6)
                ",
                &[
                    &(payload_hash.as_ref()),
                    &(slot as i32),
                    &(region_id),
                    &(proposer_pub_key.as_ref()),
                    &(message_received as i64),
                    &(payload_fetched as i64),
                ],
            )
            .await?;
        Ok(())
    }

    async fn save_delivered_payload(
        &self,
        bid_trace: &BidTrace,
        payload: Arc<ExecutionPayload>,
        latency_trace: &GetPayloadTrace,
    ) -> Result<(), DatabaseError> {
        let region_id = self.region;
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        transaction.execute(
            "
                INSERT INTO delivered_payload 
                    (block_hash, payload_parent_hash, fee_recipient, state_root, receipts_root, logs_bloom, prev_randao, timestamp, block_number, gas_limit, gas_used, extra_data, base_fee_per_gas)
                VALUES 
                    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (block_hash)
                DO NOTHING
            ",
            &[
                &(bid_trace.block_hash.as_ref()),
                &(payload.parent_hash().as_ref()),
                &(payload.fee_recipient().as_ref()),
                &(payload.state_root().as_ref()),
                &(payload.receipts_root().as_ref()),
                &(payload.logs_bloom().as_ref()),
                &(payload.prev_randao().as_ref()),
                &(payload.timestamp() as i64),
                &(payload.block_number() as i32),
                &(payload.gas_limit() as i32),
                &(payload.gas_used() as i32),
                &(payload.extra_data().as_ref()),
                &(PostgresNumeric::from(payload.base_fee_per_gas().clone())),
            ],
            ).await?;

        transaction.execute(
            "
                INSERT INTO payload_trace
                    (block_hash, region_id, receive, proposer_index_validated, signature_validated, payload_fetched, validation_complete, beacon_client_broadcast, broadcaster_block_broadcast, on_deliver_payload)
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ",
            &[
                &(bid_trace.block_hash.as_ref()),
                &(region_id),
                &(latency_trace.receive as i64),
                &(latency_trace.proposer_index_validated as i64),
                &(latency_trace.signature_validated as i64),
                &(latency_trace.payload_fetched as i64),
                &(latency_trace.validation_complete as i64),
                &(latency_trace.beacon_client_broadcast as i64),
                &(latency_trace.broadcaster_block_broadcast as i64),
                &(latency_trace.on_deliver_payload as i64),
            ],
        ).await?;

        if !payload.transactions().is_empty() {
            // Save the transactions
            let mut structured_params: Vec<(&[u8], &[u8])> = Vec::new();
            for entry in payload.transactions().iter() {
                structured_params.push((payload.block_hash().as_ref(), entry.as_ref()));
            }

            // Prepare the params vector from the structured parameters
            let params: Vec<&(dyn ToSql + Sync)> = structured_params
                .iter()
                .flat_map(|tuple| {
                    vec![&tuple.0 as &(dyn ToSql + Sync), &tuple.1 as &(dyn ToSql + Sync)]
                })
                .collect();

            // Construct the SQL statement with multiple VALUES clauses
            let mut sql = String::from("INSERT INTO transaction (block_hash, bytes) VALUES ");
            let values_clauses: Vec<String> = params
                .chunks(2)
                .enumerate()
                .map(|(i, _)| {
                    if i == 0 {
                        String::from("($1, $2)")
                    } else {
                        let offset = i * 2;
                        format!("(${}, ${})", offset + 1, offset + 2)
                    }
                })
                .collect();

            // Join the values clauses and append them to the SQL statement
            sql.push_str(&values_clauses.join(", "));

            transaction.execute(&sql, &params[..]).await?;
        }

        if payload.withdrawals().is_some() && !payload.withdrawals().unwrap().is_empty() {
            // Save the withdrawals
            let mut structured_params: Vec<(i32, &[u8], i32, &[u8], i64)> = Vec::new();
            for entry in payload.withdrawals().unwrap().iter() {
                structured_params.push((
                    entry.index as i32,
                    payload.block_hash().as_ref(),
                    entry.validator_index as i32,
                    entry.address.as_ref(),
                    entry.amount as i64,
                ));
            }

            // Prepare the params vector from the structured parameters
            let params: Vec<&(dyn ToSql + Sync)> = structured_params
                .iter()
                .flat_map(|tuple| {
                    vec![
                        &tuple.0,
                        &tuple.1 as &(dyn ToSql + Sync),
                        &tuple.2,
                        &tuple.3 as &(dyn ToSql + Sync),
                        &tuple.4,
                    ]
                })
                .collect();

            // Construct the SQL statement with multiple VALUES clauses
            let mut sql = String::from(
                "INSERT INTO withdrawal (index, block_hash, validator_index, address, amount) VALUES ",
            );
            let values_clauses: Vec<String> = params
                .chunks(5)
                .enumerate()
                .map(|(i, _)| {
                    if i == 0 {
                        String::from("($1, $2, $3, $4, $5)")
                    } else {
                        let offset = i * 5;
                        format!(
                            "(${}, ${}, ${}, ${}, ${})",
                            offset + 1,
                            offset + 2,
                            offset + 3,
                            offset + 4,
                            offset + 5
                        )
                    }
                })
                .collect();

            // Join the values clauses and append them to the SQL statement
            sql.push_str(&values_clauses.join(", "));
            sql.push_str(" ON CONFLICT (index, block_hash) DO NOTHING");

            transaction.execute(&sql, &params[..]).await?;
        }

        transaction.commit().await?;
        Ok(())
    }

    async fn store_block_submission(
        &self,
        submission: Arc<SignedBidSubmission>,
    ) -> Result<(), DatabaseError> {
        self.pool.get().await?.execute(
            "
                INSERT INTO
                    block_submission (block_number, slot_number, parent_hash, block_hash, builder_pubkey, proposer_pubkey, proposer_fee_recipient, gas_limit, gas_used, value, num_txs, timestamp)
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT (block_hash)
                DO NOTHING
                ",
            &[
                &(submission.execution_payload().block_number() as i32),
                &(submission.message.slot as i32),
                &(submission.execution_payload().parent_hash().as_ref()),
                &(submission.execution_payload().block_hash().as_ref()),
                &(submission.message.builder_public_key.as_ref()),
                &(submission.message.proposer_public_key.as_ref()),
                &(submission.message.proposer_fee_recipient.as_ref()),
                &(submission.message.gas_limit as i32),
                &(submission.message.gas_used as i32),
                &(PostgresNumeric::from(submission.message.value)),
                &(submission.execution_payload().transactions().len() as i32),
                &(submission.execution_payload().timestamp() as i64),
            ],
        ).await?;

        Ok(())
    }

    async fn save_block_submission_trace(
        &self,
        block_hash: Hash32,
        trace: SubmissionTrace,
    ) -> Result<(), DatabaseError> {
        let region_id = self.region;

        self.pool.get().await?.execute(
            "
                INSERT INTO
                    submission_trace (block_hash, region_id, receive, decode, pre_checks, signature, floor_bid_checks, simulation, auctioneer_update, request_finish)
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ",
            &[
                &(block_hash.as_ref()),
                &(region_id),
                &(trace.receive as i64),
                &(trace.decode as i64),
                &(trace.pre_checks as i64),
                &(trace.signature as i64),
                &(trace.floor_bid_checks as i64),
                &(trace.simulation as i64),
                &(trace.auctioneer_update as i64),
                &(trace.request_finish as i64),
            ],
        ).await?;
        Ok(())
    }

    async fn store_builder_info(
        &self,
        builder_pub_key: &BlsPublicKey,
        builder_info: BuilderInfo,
    ) -> Result<(), DatabaseError> {
        self.pool
            .get()
            .await?
            .execute(
                "
                    INSERT INTO builder_info (public_key, collateral, is_optimistic)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (public_key)
                    DO UPDATE SET
                        collateral = excluded.collateral,
                        is_optimistic = excluded.is_optimistic
                ",
                &[
                    &(builder_pub_key.as_ref()),
                    &(PostgresNumeric::from(builder_info.collateral)),
                    &(builder_info.is_optimistic),
                ],
            )
            .await?;

        Ok(())
    }

    async fn db_get_builder_info(
        &self,
        builder_pub_key: &BlsPublicKey,
    ) -> Result<BuilderInfo, DatabaseError> {
        match self
            .pool
            .get()
            .await?
            .query(
                "
                    SELECT * FROM builder_info 
                    WHERE public_key = $1
                ",
                &[&(builder_pub_key.as_ref())],
            )
            .await?
        {
            rows if rows.is_empty() => {
                Err(DatabaseError::BuilderInfoNotFound { public_key: builder_pub_key.clone() })
            }
            rows => parse_row(rows.get(0).unwrap()),
        }
    }

    async fn get_all_builder_infos(&self) -> Result<Vec<BuilderInfoDocument>, DatabaseError> {
        parse_rows(self.pool.get().await?.query("SELECT * FROM builder_info", &[]).await?)
    }

    async fn db_demote_builder(&self, builder_pub_key: &BlsPublicKey) -> Result<(), DatabaseError> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        transaction
            .execute(
                "
                    UPDATE builder_info 
                    SET is_optimistic = FALSE 
                    WHERE public_key = $1
                ",
                &[&(builder_pub_key.as_ref())],
            )
            .await?;

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        transaction
            .execute(
                "
                    INSERT INTO demotions (public_key, demotion_time)
                    VALUES ($1, $2)
                ",
                &[&(builder_pub_key.as_ref()), &(timestamp as i64)],
            )
            .await?;

        transaction.commit().await?;

        Ok(())
    }

    async fn save_simulation_result(
        &self,
        block_hash: ByteVector<32>,
        block_sim_result: Result<(), BlockSimError>,
    ) -> Result<(), DatabaseError> {
        if let Err(e) = block_sim_result {
            self.pool
                .get()
                .await?
                .execute(
                    "
                        INSERT INTO simulation_error (block_hash, error)
                        VALUES ($1, $2)
                        ON CONFLICT (block_hash)
                        DO NOTHING
                    ",
                    &[&(block_hash.as_ref()), &(format!("{:?}", e))],
                )
                .await?;
        }
        Ok(())
    }

    async fn get_bids(
        &self,
        filters: &BidFilters,
    ) -> Result<Vec<BidSubmissionDocument>, DatabaseError> {
        let filters = PgBidFilters::from(filters);

        parse_rows(
            self.pool
                .get()
                .await?
                .query(
                    "
                        SELECT
                            block_submission.block_number block_number,
                            block_submission.slot_number slot_number,
                            block_submission.parent_hash,
                            block_submission.block_hash,
                            block_submission.builder_pubkey builder_public_key,
                            block_submission.proposer_pubkey proposer_public_key,
                            block_submission.proposer_fee_recipient proposer_fee_recipient,
                            block_submission.gas_limit gas_limit,
                            block_submission.gas_used gas_used,
                            block_submission.value submission_value,
                            block_submission.num_txs num_txs,
                            block_submission.timestamp submission_timestamp
                        FROM 
                            block_submission 
                        WHERE 
                            ($1::integer IS NULL OR block_submission.slot_number = $1::integer)
                        AND ($2::integer IS NULL OR block_submission.block_number = $2::integer)
                        AND ($3::bytea IS NULL OR block_submission.proposer_pubkey = $3::bytea)
                        AND ($4::bytea IS NULL OR block_submission.builder_pubkey = $4::bytea)
                        AND ($5::bytea IS NULL OR block_submission.block_hash = $5::bytea)
                    ",
                    &[
                        &filters.slot(),
                        &filters.block_number(),
                        &filters.proposer_pubkey(),
                        &filters.builder_pubkey(),
                        &filters.block_hash(),
                    ],
                )
                .await?,
        )
    }

    async fn get_delivered_payloads(
        &self,
        filters: &BidFilters,
    ) -> Result<Vec<DeliveredPayloadDocument>, DatabaseError> {
        let filters = PgBidFilters::from(filters);

        parse_rows(
            self.pool
                .get()
                .await?
                .query(
                    "
                        WITH transactions_subquery AS (
                            SELECT
                                block_hash block_hash,
                                array_agg(bytes) txs
                            FROM
                                transaction
                            GROUP BY
                                block_hash
                        )
                        SELECT
                            block_submission.block_hash             block_hash,
                            block_submission.timestamp              submission_timestamp,
                            block_submission.slot_number            slot_number,
                            block_submission.block_number           block_number,
                            block_submission.parent_hash            parent_hash,
                            block_submission.builder_pubkey         builder_public_key,
                            block_submission.proposer_pubkey        proposer_public_key,
                            block_submission.proposer_fee_recipient proposer_fee_recipient,
                            block_submission.gas_limit              gas_limit,
                            block_submission.gas_used               gas_used,
                            block_submission.value                  submission_value,
                            block_submission.num_txs                num_txs,

                            delivered_payload.block_hash            payload_block_hash,
                            delivered_payload.payload_parent_hash   payload_parent_hash,
                            delivered_payload.fee_recipient         payload_fee_recipient,
                            delivered_payload.state_root            payload_state_root,
                            delivered_payload.receipts_root         payload_receipts_root,
                            delivered_payload.logs_bloom            payload_logs_bloom,
                            delivered_payload.prev_randao           payload_prev_randao,
                            delivered_payload.timestamp             payload_timestamp,
                            delivered_payload.block_number          payload_block_number,
                            delivered_payload.gas_limit             payload_gas_limit,
                            delivered_payload.gas_used              payload_gas_used,
                            delivered_payload.extra_data            payload_extra_data,
                            delivered_payload.base_fee_per_gas      payload_base_fee_per_gas,

                            transactions_subquery.txs                   txs
                        FROM 
                            delivered_payload 
                        INNER JOIN
                            block_submission 
                        ON 
                            block_submission.block_hash = delivered_payload.block_hash
                        INNER JOIN
                            transactions_subquery
                        ON
                            delivered_payload.block_hash = transactions_subquery.block_hash
                        WHERE
                            (
                                ($1::integer IS NOT NULL AND block_submission.slot_number = $1::integer) OR
                                ($1::integer IS NULL AND $2::integer IS NOT NULL AND block_submission.slot_number >= $2::integer) OR
                                ($1::integer IS NULL AND $2::integer IS NULL)
                            )
                            AND ($3::integer IS NULL OR block_submission.block_number = $3::integer)
                            AND ($4::bytea IS NULL OR block_submission.proposer_pubkey = $4::bytea)
                            AND ($5::bytea IS NULL OR block_submission.builder_pubkey = $5::bytea)
                            AND ($6::bytea IS NULL OR block_submission.block_hash = $6::bytea)
                        ORDER BY
                            CASE
                                WHEN $7 >= 0 THEN block_submission.value
                                ELSE NULL
                            END ASC,
                            CASE
                                WHEN $7 < 0 THEN block_submission.value
                                ELSE NULL
                            END DESC
                        LIMIT
                            CASE
                                WHEN $8::bigint IS NOT NULL THEN $8::bigint
                                ELSE NULL
                            END
                    ",
                    &[
                        &filters.slot(),
                        &filters.cursor(),
                        &filters.block_number(),
                        &filters.proposer_pubkey(),
                        &filters.builder_pubkey(),
                        &filters.block_hash(),
                        &filters.order(),
                        &filters.limit()
                    ],
                )
                .await?,
        )
    }
}
