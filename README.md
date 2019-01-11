# pouchdb-dac
Distributed access control for PouchDB

Strategy

--write access is hanlded by restricting writes into the DB.
      Override 'put' in database so that only documents that are
      "correctly signed" can be written.  "Correctly" implies that if an
      existing document has an attribute ACU_OWNER (indicating
      ownership), then any overwrites of that document require signing
      by some owner listed in that attribute.

--read access is handled by encryption.  Sensitive attributes of
      the document are (optionally) symetrically encrypted, and a key is stored for each
      potential reader asymetrically encrypted with their public key.
      During decrypt, each secret key in the user's
      possession is checked to see if it can decrypt a key that can be
      used to decrypt the document.

Encryption and signing is provided by another module.  See
'pouch-dac-nacl' for an example.

     npm install pouchdb-dac pouchdb-dac-nacl --save
     
Use:

```javascript

    var PouchDB = require("pouchdb");
    var pouchDAC = require("pouchdb-dac");
    var pouchNaCl = require("pouchdb-dac-nacl");

    var db = new PouchDB("test");
    //install DAC into db instance with NaCl encryption
    pouchDAC.installPlugin(db,pouchNaCl.encryptionProvider());

    //create some credentials (in practice this would be elsewhere and
    //they would be saved
    var one_cred = db.newCredential(); 
    var other_cred = db.newCredential(); 
    db.addCredential(one_cred);
    db.addCredential(other_cred);

    db.get(uu).then(doc => { //get a document
      doc.foo = "hello" + doc.foo;  //make some change
      doc = db.addOwner(doc,test_cred.id);  //add an owner

      //optionally encrypt
      doc = db.encryptDoc(doc,one_cred.id, [one_cred.id, other_cred.id], '*');
      
      db.signDoc(doc).then(doc => {  //sign it before putting
         db.put(doc) 
         ...
```

