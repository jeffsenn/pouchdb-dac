'use strict';

//this is mysteriously broken sometimes
//var Promise = require('pouchdb-promise');
var wrappers = require('pouchdb-wrappers');

const ACU_OWNER = "acu_owner"
const ACU_SIGNATURE = "acu_signature"
const ENCRYPTED_CONTENT = "encrypted_content"
const ENCRYPTED_ATTRS = "encrypted_attributes"
const ENCRYPTED_READERS = "encrypted_readers"
const DONT_ENCRYPT = [ENCRYPTED_CONTENT,ACU_SIGNATURE,ACU_OWNER];

//this version like JSON.stringify except keys are canonically ordered (lexically)
var orderedJSONStringify = function(o,filterkeys) {
  if(Array.isArray(o)) {
    return "["+ o.map((a) => orderedJSONStringify(a)).join(',')+"]";
  } else if(typeof o === 'object') {
    var k = Object.entries(o);
    if(filterkeys) {
      k = k.filter(function(a) { return filterkeys(a[0]); });
    }
    return "{"+k.map(function(a) { return '"' + a[0] + '":' + orderedJSONStringify(a[1]); }).sort().join(",") + "}";
  } else {
    var ret = JSON.stringify(o);
    return ret || "null";
  }
}
exports.orderedJSONStringify = orderedJSONStringify;

var isSuperSet = function(superset, subset) {
  return subset.every(function(el) { return superset.indexOf(el) > -1; });
};

var uuidv4 = function() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

//See 'pouch-dac-nacl' for example of encryptionProvider
exports.installPlugin = function (db, encryptionProvider) {

  if (db.adapter.startsWith('http')) {
    throw "POUCHDAC: use only for local db";
  }

  db.addOwner = function(doc, owner) {
    if(doc[ACU_OWNER]) {
      if(doc[ACU_OWNER].indexOf(owner) < 0) {
        doc[ACU_OWNER] = doc[ACU_OWNER].slice(0);
        doc[ACU_OWNER].push(owner);
      } //otherwise there already
    } else {
      doc[ACU_OWNER] = [owner];
    }
    return doc;
  };

  db.signDoc = function(doc) {
    let owners = doc[ACU_OWNER];
    if(!owners || !owners.length) return doc; //no signing if no owners
    if(!doc._id) doc._id = uuidv4();
    var doc_stringify = orderedJSONStringify(doc, function(k) {return k != '_rev' && k != ACU_SIGNATURE && k != '_rev_tree'});
    var hash = encryptionProvider.hash(doc_stringify);
    return encryptionProvider.sign(owners, hash).then(sig => {
      doc[ACU_SIGNATURE] = sig;
      return doc;
    });
  };

  db.encryptDoc = function(doc, writer, readers, encrypted_attrs) {
    var ret = {};
    encrypted_attrs = encrypted_attrs || doc[ENCRYPTED_ATTRS];
    readers = readers || doc[ACU_OWNER] || doc[ENCRYPTED_READERS];
    if(encrypted_attrs) {
        var encrypted = [], non_encrypted = [];
        if (Array.isArray(encrypted_attrs)) {
	  if(encrypted_attrs[0] == '*') {
            encrypted = Object.keys(doc);
            non_encrypted = encrypted_attrs.slice(1);
          } else {
            encrypted = encrypted_attrs;
          }
        } else if (encrypted_attrs === '*') {
          encrypted = Object.keys(doc);
        }
      //remove encrypted attrs into another object
      doc = Object.assign({},doc); //non-destruct copy
      encrypted.forEach(f => {
        if(!f.startsWith("_") && DONT_ENCRYPT.indexOf(f) < 0 && non_encrypted.indexOf(f) < 0) {
          ret[f] = doc[f];
          delete doc[f];
        }
      });
      doc[ENCRYPTED_CONTENT] = encryptionProvider.encrypt(ret, writer, readers);
    }
    return doc;
  };

  db.decryptDoc = function(encrypted_doc) {
    var encrypted = encrypted_doc[ENCRYPTED_CONTENT];
    var ret = encrypted_doc;
    if(encrypted) {
      var doc = encryptionProvider.decrypt(encrypted);
      if(doc) {
        //merge with source doc
        ret = Object.assign({[ENCRYPTED_ATTRS]: Object.keys(doc)}, doc, ret);
        delete ret[ENCRYPTED_CONTENT];
      }
    };
    //TODO should it return decrypt id? note also this just returns encrypted rather than failing
    return ret;
  };

  db.newCredential = function(p) {
    return encryptionProvider.newCredential(p);
  };
    db.addCredential = function(c,p) {
	return encryptionProvider.addCredential(c,p);
  };
  db.removeCredential = function(id) {
    return encryptionProvider.removeCredential(id);
  };

  wrappers.installWrapperMethods(db, {
    bulkDocs : function (orig, args) {
      for (var i = 0; i < args.docs.length; i++) {
        var new_doc = args.docs[i];
        //TODO: deal with doc._deleted
        if(new_doc._id && !(typeof new_doc._id === 'string' && (/^_local/).test(new_doc._id))) {
          var orig_doc;
          args.docs[i] = new Promise((resolve, reject) => {
            var orig_doc;
            db.get(args.docs[i]._id).then(doc => {
              orig_doc = doc;
            }).catch(e => {
              if(e.status && e.status == 404) {
                orig_doc = null;
              } else {
                throw(e);
              }
            }).finally(() => {
              if(orig_doc && orig_doc[ACU_OWNER] && ! isSuperSet(new_doc[ACU_OWNER], orig_doc[ACU_OWNER])  ) {
                //allow only grabbing an anonymous doc
                console.log("POUCHDAC: Rejecting owner change",new_doc._id, orig_doc[ACU_OWNER], new_doc[ACU_OWNER]);
                resolve(null);
              } else if(new_doc[ACU_OWNER]) { //verify signature
                var doc_stringify = orderedJSONStringify(new_doc, function(k) {return k != '_rev' && k != ACU_SIGNATURE && k != '_rev_tree'});
                var hash = encryptionProvider.hash(doc_stringify);
                var signed_by = encryptionProvider.verify(hash, new_doc[ACU_SIGNATURE]);

                if(signed_by && (
                    (orig_doc &&
                     orig_doc[ACU_OWNER] &&
                     orig_doc[ACU_OWNER].indexOf(signed_by) > -1) ||
                        ((!orig_doc || !orig_doc[ACU_OWNER]) &&
                         new_doc[ACU_OWNER].indexOf(signed_by) > -1))) {
                  resolve(new_doc);
                } else {
                  console.log("POUCHDAC: Rejecting invalid doc", new_doc._id, signed_by, new_doc[ACU_OWNER], new_doc[ACU_SIGNATURE]);
                  resolve(null);
                }
              } else { //anonymous doc ok
                resolve(new_doc);
              }
            });
          });
 	}
      }
      return Promise.all(args.docs).then(function (docs) {
        args.docs = docs.filter(function(v,i,a) { return v;}); //filter null docs removed by verify
        return orig();
      });
    }
  });
}
