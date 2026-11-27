# The Rust wrappers, native sys crate, and JWT facade must all refer to
# the same Git source identity. Reqsign packages must likewise share their
# reviewed generated family, even when not active in a particular release.
def family($names; $source_pattern):
    .packages as $packages
    | [$names[] as $name | [$packages[] | select(.name == $name)]] as $members
    | if all($members[]; length == 1) then
          [$members[][] | .source] | unique
          | if length == 1 and (.[0] | type == "string" and test($source_pattern))
            then .[0]
            else error("inconsistent source identities for " + ($names | join(", ")) + ": " + tostring)
            end
      else error("missing or duplicate package in " + ($names | join(", ")) + ": " + ($members | map(map({name,version,source})) | tostring))
      end;
{
    btls: family(["btls","btls-sys","tokio-btls","jsonwebtoken-btls"]; "^git\\+https://github\\.com/codeandsolder/btls-fast\\.git\\?rev=[a-f0-9]{40}#[a-f0-9]{40}$"),
    wreq: family(["wreq"]; "^git\\+https://github\\.com/codeandsolder/wreq-exp\\.git\\?rev=[a-f0-9]{40}#[a-f0-9]{40}$"),
    reqsign: family(["reqsign-core","reqsign-google","reqsign-azure-storage"]; "^git\\+https://github\\.com/codeandsolder/cargo-patches\\.git\\?rev=[a-f0-9]{40}#[a-f0-9]{40}$")
}
