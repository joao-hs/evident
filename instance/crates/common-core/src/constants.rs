// Assumption: /etc/evident/pki/ is inside (or mounted as) a tpmfs (or similar RAM-based filesystem)
macro_rules! pki_dir {
    () => {
        "/etc/evident/pki"
    };
}

macro_rules! private_dir {
    ($base:expr) => {
        concat!($base, "/private")
    };
}
macro_rules! public_dir {
    ($base:expr) => {
        concat!($base, "/public")
    };
}

macro_rules! instance_dir {
    () => {
        concat!(pki_dir!(), "/instance")
    };
}
macro_rules! grpc_dir {
    () => {
        concat!(pki_dir!(), "/grpc")
    };
}

pub const INSTANCE_PRIVATE_KEY_PATH: &str =
    concat!(private_dir!(instance_dir!()), "/instance.key.der");
pub const INSTANCE_PUBLIC_KEY_PATH: &str =
    concat!(public_dir!(instance_dir!()), "/instance.pub.der");
pub const INSTANCE_CERTIFICATE_PATH: &str =
    concat!(public_dir!(instance_dir!()), "/instance.crt.pem");
pub const INSTANCE_SELF_SIGNED_CERTIFICATE_PATH: &str =
    concat!(public_dir!(instance_dir!()), "/instance-root.crt.pem");
pub const INSTANCE_CERTIFICATE_SIGNING_REQUEST_PATH: &str =
    concat!(public_dir!(instance_dir!()), "/instance.csr.pem");

pub const GRPC_EVIDENT_SERVER_PRIVATE_KEY_PATH: &str =
    concat!(private_dir!(grpc_dir!()), "/grpc.key.pem");
pub const GRPC_EVIDENT_SERVER_PUBLIC_KEY_PATH: &str =
    concat!(public_dir!(grpc_dir!()), "/grpc.pub.pem");
pub const GRPC_EVIDENT_SERVER_CERTIFICATE_PATH: &str =
    concat!(public_dir!(grpc_dir!()), "/grpc.crt.pem");

pub const EVIDENT_SERVER_PORT: u16 = 5000;
