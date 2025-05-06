// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, Vote};
use config::{Committee, Stake};
use crypto::{PublicKey, Signature};
use std::collections::HashSet;
use log::debug;
use std::collections::BTreeMap;

pub fn update_authorities_mask(committee: &Committee) -> BTreeMap<PublicKey, bool> {
    use rand::seq::SliceRandom;
    
    let mut mask = BTreeMap::new();
    let quorum_size = committee.quorum_threshold() as usize;
    
    // Get all authority keys except the last one
    let mut keys: Vec<PublicKey> = committee.authorities.keys().take(committee.authorities.len() - 3).cloned().collect();
    keys.shuffle(&mut rand::rng());
    
    // Initialize all authorities to false
    for key in &keys {
        mask.insert(*key, false);
    }
    
    // Randomly select 'quorum_size' authorities to set to true
    for i in 0..quorum_size {
        if i < keys.len() {
            mask.insert(keys[i], true);
        }
    }
    
    mask
}

/// Aggregates votes for a particular header into a certificate.
pub struct VotesAggregator {
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
    mask: BTreeMap<PublicKey, bool>,
}

impl VotesAggregator {
    pub fn new(committee: &Committee) -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
            mask: update_authorities_mask(committee),
        }
    }

    pub fn append(
        &mut self,
        vote: Vote,
        committee: &Committee,
        header: &Header,
    ) -> DagResult<Option<Certificate>> {
        let author = vote.author;

        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.votes.push((author, vote.signature));
        self.weight += committee.stake_with_mask(&author, &self.mask);
        if self.weight >= committee.quorum_threshold() {
            debug!("Quorum {:?}", self.votes);
            self.weight = 0; // Ensures quorum is only reached once.
            return Ok(Some(Certificate {
                header: header.clone(),
                votes: self.votes.clone(),
            }));
        }
        Ok(None)
    }
}

/// Aggregate certificates and check if we reach a quorum.
pub struct CertificatesAggregator {
    weight: Stake,
    certificates: Vec<Certificate>,
    used: HashSet<PublicKey>,
}

impl CertificatesAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            certificates: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        certificate: Certificate,
        committee: &Committee,
    ) -> DagResult<Option<Vec<Certificate>>> {
        let origin = certificate.origin();

        // Ensure it is the first time this authority votes.
        if !self.used.insert(origin) {
            return Ok(None);
        }

        self.certificates.push(certificate);
        self.weight += committee.stake(&origin);
        if self.weight >= committee.quorum_threshold() {
            //self.weight = 0; // Ensures quorum is only reached once.
            return Ok(Some(self.certificates.drain(..).collect()));
        }
        Ok(None)
    }
}
