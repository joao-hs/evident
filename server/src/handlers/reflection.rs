use tonic_reflection::server::{
    Builder, Error,
    v1::{ServerReflection, ServerReflectionServer},
};

pub fn create_reflection_service() -> Result<ServerReflectionServer<impl ServerReflection>, Error> {
    Builder::configure()
        .register_encoded_file_descriptor_set(include_bytes!("../../proto/descriptor.bin"))
        .build_v1()
}
