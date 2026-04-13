use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::Result;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    pub peer_did: String,
    pub alpha: f64,
    pub beta: f64,
    pub last_interaction: u64,
    pub mu_ping: f64,    // Moving average ping in ms
    pub sigma_jitter: f64, // Moving average jitter in ms
    pub success_streak: u32,
    pub frozen_until: u64, // Unix timestamp in ms
}

impl ReputationScore {
    pub fn expected_value(&self) -> f64 {
        if self.alpha + self.beta == 0.0 {
            0.5 // Default unknown
        } else {
            self.alpha / (self.alpha + self.beta)
        }
    }

    /// Calculates the maximum allowed timeout for an institutional-grade canary audit.
    pub fn get_t_max(&self) -> f64 {
        self.mu_ping + (3.0 * self.sigma_jitter) + 50.0
    }

    pub fn is_frozen(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.frozen_until > now
    }
}

#[derive(Clone)]
pub struct ReputationManager {
    db_path: PathBuf,
    scores: Arc<DashMap<String, ReputationScore>>,
}

impl ReputationManager {
    /// Initialize the manager and load scores from JSON if they exist.
    pub async fn new(db_path: PathBuf) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        
        let scores = Arc::new(DashMap::new());
        
        if db_path.exists() {
            let data = tokio::fs::read(&db_path).await?;
            let loaded_scores: Vec<ReputationScore> = serde_json::from_slice(&data)?;
            for score in loaded_scores {
                scores.insert(score.peer_did.clone(), score);
            }
        }

        Ok(Self { db_path, scores })
    }

    /// Decay mechanism applying gamma = 0.95 ^ hours elapsed.
    fn apply_decay(score: &mut ReputationScore, current_time: u64) {
        let elapsed_seconds = current_time.saturating_sub(score.last_interaction);
        let elapsed_hours = elapsed_seconds as f64 / 3600.0;
        
        if elapsed_hours >= 1.0 {
            let gamma = 0.95_f64.powf(elapsed_hours);
            score.alpha = 1.0 + (score.alpha - 1.0) * gamma;
            score.beta = 1.0 + (score.beta - 1.0) * gamma;
            score.last_interaction = current_time;
        }
    }

    pub async fn get_score(&self, peer_did: String) -> Result<ReputationScore> {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        let entry = self.scores.entry(peer_did.clone()).or_insert(ReputationScore {
            peer_did: peer_did.clone(),
            alpha: 1.0,
            beta: 1.0,
            last_interaction: current_time,
            mu_ping: 100.0, // Default 100ms
            sigma_jitter: 10.0, // Default 10ms
            success_streak: 0,
            frozen_until: 0,
        });
        
        let mut score = entry.value().clone();
        Self::apply_decay(&mut score, current_time);
        Ok(score)
    }

    /// Applies the result of an Ephemeral Canary audit.
    pub async fn apply_canary_result(&self, peer_did: String, success: bool, latency_ms: f64) -> Result<()> {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        {
            let mut entry = self.scores.entry(peer_did.clone()).or_insert(ReputationScore {
                peer_did: peer_did.clone(),
                alpha: 1.0,
                beta: 1.0,
                last_interaction: current_time,
                mu_ping: latency_ms,
                sigma_jitter: 5.0,
                success_streak: 0,
                frozen_until: 0,
            });
            
            let score = entry.value_mut();
            if score.is_frozen() {
                return Ok(());
            }
            Self::apply_decay(score, current_time);
            
            if success {
                // Success: Asymmetric Alpha Streak
                // alpha_new = alpha_old + min(n * 0.5, 2.5)
                score.success_streak += 1;
                let gain = (score.success_streak as f64 * 0.5).min(2.5);
                score.alpha += gain;
                
                // Update moving average (alpha=0.2 smoothing)
                score.mu_ping = (score.mu_ping * 0.8) + (latency_ms * 0.2);
                let diff = (latency_ms - score.mu_ping).abs();
                score.sigma_jitter = (score.sigma_jitter * 0.8) + (diff * 0.2);
            } else {
                // Failure: Bounded Beta Penalty
                // Cap beta penalties for "Late-but-Valid" packets at +2.0 per event.
                score.beta += 2.0;
                score.success_streak = 0;
                info!("[REPUTATION] Peer {} slashed (beta +2.0) due to latency/drop.", peer_did);
            }
            score.last_interaction = current_time;
        }

        self.save().await?;
        Ok(())
    }

    pub async fn update_score(&self, peer_did: String, positive: bool) -> Result<()> {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        {
            let mut entry = self.scores.entry(peer_did.clone()).or_insert(ReputationScore {
                peer_did: peer_did.clone(),
                alpha: 1.0,
                beta: 1.0,
                last_interaction: current_time,
                mu_ping: 100.0,
                sigma_jitter: 10.0,
                success_streak: 0,
                frozen_until: 0,
            });
            
            let score = entry.value_mut();
            Self::apply_decay(score, current_time);
            
            if positive {
                score.alpha += 1.0;
            } else {
                score.beta += 1.0;
            }
            score.last_interaction = current_time;
        }

        self.save().await?;
        Ok(())
    }

    async fn save(&self) -> Result<()> {
        let all_scores: Vec<ReputationScore> = self.scores.iter().map(|kv| kv.value().clone()).collect();
        let data = serde_json::to_vec_pretty(&all_scores)?;
        tokio::fs::write(&self.db_path, data).await?;
        Ok(())
    }

    pub async fn check_threshold(&self, peer_did: String) -> Result<bool> {
        let score = self.get_score(peer_did).await?;
        Ok(score.expected_value() >= 0.4)
    }

    pub async fn get_all_scores(&self) -> Result<Vec<ReputationScore>> {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut results = Vec::new();
        
        for mut kv in self.scores.iter_mut() {
            let score = kv.value_mut();
            Self::apply_decay(score, current_time);
            results.push(score.clone());
        }
        
        Ok(results)
    }

    /// Suspend all reputation recalculations for a peer for a specified duration.
    pub async fn freeze_peer(&self, peer_did: String, duration_ms: u64) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        let mut entry = self.scores.entry(peer_did.clone()).or_insert(ReputationScore {
            peer_did: peer_did.clone(),
            alpha: 1.0,
            beta: 1.0,
            last_interaction: now / 1000,
            mu_ping: 100.0,
            sigma_jitter: 10.0,
            success_streak: 0,
            frozen_until: 0,
        });

        entry.value_mut().frozen_until = now + duration_ms;
        info!("[REPUTATION] Peer {} FROZEN for {}ms.", peer_did, duration_ms);
        Ok(())
    }

    /// High-gravity slashing for cryptographic failures (Invalid MAC or Signature).
    pub async fn apply_auth_failure(&self, peer_did: String) -> Result<()> {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        {
            let mut entry = self.scores.entry(peer_did.clone()).or_insert(ReputationScore {
                peer_did,
                alpha: 1.0,
                beta: 1.0,
                last_interaction: current_time,
                mu_ping: 100.0,
                sigma_jitter: 10.0,
                success_streak: 0,
                frozen_until: 0,
            });

            let score = entry.value_mut();
            score.beta += 10.0;
            score.success_streak = 0;
            info!("[REPUTATION] Peer {} isolated due to AUTHENTICATION_FAILURE (beta +10.0).", entry.key());
        }
        self.save().await?;
        Ok(())
    }
}
