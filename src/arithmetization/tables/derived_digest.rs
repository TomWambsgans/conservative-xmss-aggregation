use super::n_vars_for;
use crate::{
    arithmetization::channels::Channels,
    utils::{
        fill_multiple_witness_col, fill_rows, fill_witness_col, B16, B64, KECCAK256_PADDING_LEFT,
        KECCAK256_PADDING_RIGHT,
    },
    xmss::XmssVerificationWitness,
};
use array_init::array_init;
use binius_circuits::{
    builder::{witness, ConstraintSystemBuilder},
    transparent,
};
use binius_core::oracle::OracleId;
use binius_field::{Field, TowerField};

#[derive(Clone, Debug)]
pub struct DerivedDigestTable {
    pub count: usize,
    pub n_vars: usize,
    pub msg_digest: [OracleId; 4],             // each is 8-bytes
    pub nonce: OracleId,                       // 8-bytes
    pub derived_msg_digest: [OracleId; 4],     // each is 8-bytes
    pub signature_index: OracleId,             // 2 bytes
    pub keccak_truncated_bits: [OracleId; 21], // each is 8-bytes
}

impl super::Table for DerivedDigestTable {
    fn count(&self) -> usize {
        self.count
    }

    fn n_vars(&self) -> usize {
        self.n_vars
    }

    fn build<'arena>(
        builder: &mut ConstraintSystemBuilder<'arena>,
        channels: &Channels,
        aggregation_count: usize,
    ) -> Self {
        builder.push_namespace("chain_head_table");

        let count = aggregation_count;
        let n_vars = n_vars_for::<B16>(count);

        let res = Self {
            count,
            n_vars,
            msg_digest: builder.add_committed_multiple("msg_digest", n_vars, B64::TOWER_LEVEL),
            nonce: builder.add_committed("nonce", n_vars, B64::TOWER_LEVEL),
            derived_msg_digest: builder.add_committed_multiple(
                "msg_digest",
                n_vars,
                B64::TOWER_LEVEL,
            ),
            signature_index: builder.add_committed("signature_index", n_vars, B16::TOWER_LEVEL),
            keccak_truncated_bits: builder.add_committed_multiple(
                "keccak_truncated_bits",
                n_vars,
                B64::TOWER_LEVEL,
            ),
        };

        // we need to padd with 0x01 00000 ... 0000 0x80 ro reach the rate of 136 bytes
        let keccak_padding_0x01 = transparent::constant(
            builder,
            "padding-0x01",
            n_vars,
            B64::from(KECCAK256_PADDING_LEFT),
        )
        .unwrap();
        let keccak_padding_0x80 = transparent::constant(
            builder,
            "padding-0x80",
            n_vars,
            B64::from(KECCAK256_PADDING_RIGHT),
        )
        .unwrap();
        let zeros = transparent::constant(builder, "zeros", n_vars, B64::ZERO).unwrap();

        builder
            .send(channels.keccakf, count, {
                let mut oracle_ids = [0; 50];
                // input
                oracle_ids[0..4].copy_from_slice(&res.msg_digest);
                oracle_ids[4] = res.nonce;
                oracle_ids[5..25].copy_from_slice(&[zeros; 20]);
                oracle_ids[5] = keccak_padding_0x01;
                oracle_ids[16] = keccak_padding_0x80;
                // output
                oracle_ids[25..29].copy_from_slice(&res.derived_msg_digest);
                oracle_ids[29..50].copy_from_slice(&res.keccak_truncated_bits);

                oracle_ids
            })
            .unwrap();

        builder
            .receive(channels.derived_message_digest, count, {
                let mut oracle_ids = res.derived_msg_digest.to_vec();
                oracle_ids.push(res.signature_index);
                oracle_ids
            })
            .unwrap();

        builder
            .send(channels.message_digest, count, {
                let mut oracle_ids = res.msg_digest.to_vec();
                oracle_ids.push(res.signature_index);
                oracle_ids
            })
            .unwrap();

        builder.pop_namespace();

        res
    }

    fn fill<'arena>(
        &self,
        witness_builder: &mut witness::Builder<'arena>,
        xmss_witnesses: &[XmssVerificationWitness],
    ) {
        let mut msg_digest = array_init::<_, _, 4>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut nonce = vec![B64::ZERO; 1 << self.n_vars];
        let mut derived_msg_digest = array_init::<_, _, 4>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut signature_index = vec![B16::ZERO; 1 << self.n_vars];
        let mut keccak_truncated_bits =
            array_init::<_, _, 21>(|_| vec![B64::ZERO; 1 << self.n_vars]);

        for signature_idx in 0..xmss_witnesses.len() {
            let witness = &xmss_witnesses[signature_idx];
            fill_rows(&mut msg_digest, signature_idx, witness.wots.msg_digest);
            nonce[signature_idx] = B64::from(witness.wots.nonce);
            fill_rows(
                &mut derived_msg_digest,
                signature_idx,
                witness.wots.derived_digest,
            );
            signature_index[signature_idx] = B16::from(signature_idx as u16);
            fill_rows(
                &mut keccak_truncated_bits,
                signature_idx,
                witness.wots.derived_digest_keccak_truncated_bits,
            );
        }

        fill_multiple_witness_col(witness_builder, self.msg_digest, msg_digest);
        fill_witness_col(witness_builder, self.nonce, nonce);
        fill_multiple_witness_col(witness_builder, self.derived_msg_digest, derived_msg_digest);
        fill_witness_col(witness_builder, self.signature_index, signature_index);
        fill_multiple_witness_col(
            witness_builder,
            self.keccak_truncated_bits,
            keccak_truncated_bits,
        );
    }
}
