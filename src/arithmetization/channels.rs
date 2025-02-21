use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::constraint_system::channel::ChannelId;

#[derive(Clone, Debug)]
pub struct Channels {
    pub keccakf: ChannelId,
    pub merkle: ChannelId,
    pub message_digest: ChannelId,
    pub lookup_channel: ChannelId,
    pub derived_message_digest: ChannelId,
    pub hash_chain_counter: ChannelId,
}

impl Channels {
    pub fn build<'arena>(builder: &mut ConstraintSystemBuilder<'arena>) -> Self {
        Self {
            keccakf: builder.add_channel(),
            merkle: builder.add_channel(),
            message_digest: builder.add_channel(),
            lookup_channel: builder.add_channel(),
            derived_message_digest: builder.add_channel(),
            hash_chain_counter: builder.add_channel(),
        }
    }
}
