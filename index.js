'use strict';

//this is mysteriously broken sometimes
//var Promise = require('pouchdb-promise');
var wrappers = require('pouchdb-wrappers');

const ACU_OWNER = "acu_owner"
const ACU_SIGNATURE = "acu_signature"
const ENCRYPTED_CONTENT = "encrypted_content"
const ENCRYPTED_ATTRS = "encrypted_attributes"
const DONT_ENCRYPT = [ENCRYPTED_CONTENT,ACU_SIGNATURE,ACU_OWNER];
                      
//this version like JSON.stringify except keys are canonically ordered (lexically)
var orderedJSONStringify = function(o,filterkeys) {
  if(Array.isArray(o)) {
    return "["+ o.map(orderedJSONStringify).join(',')+"]";
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

//See 'pouch-dac-nacl' for example of encryptionProvider
exports.installPlugin = function (db, encryptionProvider) {
  if (db.type().startsWith('http')) {
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
    var doc_stringify = orderedJSONStringify(doc, function(k) {return k != '_rev' && k != ACU_SIGNATURE && k != '_rev_tree'});
    var hash = encryptionProvider.hash(doc_stringify);
    return encryptionProvider.sign(doc[ACU_OWNER], hash).then(sig => {
      doc[ACU_SIGNATURE] = sig;
      return doc;
    });
  };
  
  db.encryptDoc = function(doc, writer, readers, encrypted_attrs) {
    var ret = {};
    encrypted_attrs = encrypted_attrs || doc.encrypted_attrs;
    if(encrypted_attrs) {
      //remove encrypted attrs into another object
      if (encrypted_attrs === '*') {
        var new_doc = {};
        Object.keys(doc).forEach(f => {
          if(f.startsWith("_") || DONT_ENCRYPT.indexOf(f) > -1) {
            new_doc[f] = doc[f];
          } else {
            ret[f] = doc[f];
          }
        })
        doc = new_doc;
      } else {
        doc = Object.assign({},doc);        
        for (var i = 0; i < encrypted_attrs.length; i++) {
          ret[encrypted_attrs[i]] = doc[encrypted_attrs[i]];
          delete doc[encrypted_attrs[i]];
        }
      }
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
        if(!(typeof new_doc._id === 'string' && (/^_local/).test(new_doc._id))) {
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
                if(signed_by && ((orig_doc[ACU_OWNER] && orig_doc[ACU_OWNER].indexOf(signed_by) > -1) || (!orig_doc[ACU_OWNER] && new_doc[ACU_OWNER].indexOf(signed_by) > -1))) {
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

  


