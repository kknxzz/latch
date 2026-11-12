use super::*;

fn device(name: &str) -> (Session, Identity) {
    // Synthetic keys generated only in tests. Production imports Go's device key.
    use ed25519_dalek::SigningKey;
    let seed = [name.as_bytes()[0];32];
    let key = SigningKey::from_bytes(&seed).verifying_key().to_bytes().to_vec();
    let id = Identity {credential:name.as_bytes().to_vec(),public_key:key};
    (Session::new(id.clone(), &seed).unwrap(),id)
}

fn pair() -> (Session,Identity,Session,Identity) {
    let (mut a,ai)=device("alice");let (mut b,bi)=device("bob");
    a.create(&[1;16]).unwrap();
    let kp=b.key_package().unwrap();let change=a.add(&kp,&bi).unwrap();
    b.join(&change.welcome,&[1;16],&ai.public_key,&[ai.clone(),bi.clone()]).unwrap();
    (a,ai,b,bi)
}

#[test]
fn exchange_tamper_replay_and_update() {
    let (mut a,ai,mut b,bi)=pair();
    let ciphertext=a.encrypt(b"confidential canary").unwrap();
    assert!(!ciphertext.windows(19).any(|w|w==b"confidential canary"));
    let mut tampered=ciphertext.clone();let n=tampered.len();tampered[n-1]^=1;
    assert!(b.decrypt(&tampered).is_err());
    let plain=b.decrypt(&ciphertext).unwrap();assert_eq!(plain.plaintext,b"confidential canary");
    assert!(plain.sender==ai);assert!(b.decrypt(&ciphertext).is_err());
    let old=b.encrypt(b"old epoch").unwrap();
    let change=a.update().unwrap();b.process_commit(&change.commit,&[ai.clone(),bi]).unwrap();
    assert!(a.decrypt(&old).is_err());
    let reply=b.encrypt(b"new epoch").unwrap();assert_eq!(a.decrypt(&reply).unwrap().plaintext,b"new epoch");
}

#[test]
fn join_cannot_read_past_and_removed_member_cannot_read_future() {
    let (mut a,ai,mut b,bi)=pair();let (mut c,ci)=device("charlie");
    let past=a.encrypt(b"before charlie").unwrap();
    let kp=c.key_package().unwrap();let change=a.add(&kp,&ci).unwrap();
    let roster=vec![ai.clone(),bi.clone(),ci.clone()];
    b.process_commit(&change.commit,&roster).unwrap();
    c.join(&change.welcome,&[1;16],&ai.public_key,&roster).unwrap();
    assert!(c.decrypt(&past).is_err());
    let change=a.remove(&bi.public_key).unwrap();
    c.process_commit(&change.commit,&[ai,ci]).unwrap();
    let future=a.encrypt(b"after bob").unwrap();
    assert!(b.decrypt(&future).is_err());assert_eq!(c.decrypt(&future).unwrap().plaintext,b"after bob");
}

#[test]
fn rejects_key_substitution_wrong_group_and_roster() {
    let (mut a,ai)=device("alice");let (mut b,bi)=device("bob");let (_,ci)=device("charlie");
    a.create(&[1;16]).unwrap();let kp=b.key_package().unwrap();
    assert!(a.add(&kp,&ci).is_err());
    let change=a.add(&kp,&bi).unwrap();
    assert!(b.join(&change.welcome,&[2;16],&ai.public_key,&[ai.clone(),bi]).is_err());
    assert!(a.validate_members(&[ai]).is_err());
}

#[test]
fn non_host_cannot_commit_membership() {
    let (mut a,ai,mut b,bi)=pair();
    assert!(b.update().is_err());assert!(b.remove(&ai.public_key).is_err());
    assert!(a.remove(&ai.public_key).is_err());
    let mut host_change=a.update().unwrap();host_change.commit.push(0);
    assert!(b.process_commit(&host_change.commit,&[ai,bi]).is_err());
}

#[test]
fn input_and_session_bounds() {
    let (mut a,_,mut b,_)=pair();
    assert!(a.encrypt(&[]).is_err());assert!(a.encrypt(&[b'x';4097]).is_err());
    assert!(a.encrypt(&[255]).is_err());assert!(b.key_package().is_err());
    for bytes in [vec![],vec![0],vec![255;32769]] {
        assert!(b.decrypt(&bytes).is_err());assert!(b.process_commit(&bytes,&[]).is_err());
    }
}
