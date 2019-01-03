'use strict';

var Promise = require('pouchdb-promise');
var wrappers = require('pouchdb-wrappers');
const ACU_OWNER = "acu_owner"
const ACU_SIGNATURE = "acu_signature"

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

//
// signing_provider must provide:
//   sign(owner_string, document_hash_string) --> signature_string
//   verify(owner_string, document_hash_string, signature_string)
//   hash(document_string) --> document_hash_string
//
exports.installPlugin = function (db, signing_provider) {
  if (db.type().startsWith('http')) {
    throw "POUCHDAC: use only for local db";
  }

  db.addOwner = function(doc, owner) {
    doc[ACU_OWNER] = owner;
    return doc;
  };
  
  db.signDoc = function(doc) {
    var doc_stringify = orderedJSONStringify(doc, function(k) {return k != '_rev' && k != ACU_SIGNATURE && k != '_rev_tree'});
    var hash = signing_provider.hash(doc_stringify);
    return signing_provider.sign(doc[ACU_OWNER], hash).then(sig => {
      doc[ACU_SIGNATURE] = sig;
      return doc;
    });
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
              if(orig_doc && orig_doc[ACU_OWNER] != new_doc[ACU_OWNER] && orig_doc[ACU_OWNER]) {
                //allow only grabbing an anonymous doc
                console.log("POUCHDAC: Rejecting owner change",new_doc._id, orig_doc[ACU_OWNER], new_doc[ACU_OWNER]);
                resolve(null);
              } else if(new_doc[ACU_OWNER]) { //verify signature
                var doc_stringify = orderedJSONStringify(new_doc, function(k) {return k != '_rev' && k != ACU_SIGNATURE && k != '_rev_tree'});
                var hash = signing_provider.hash(doc_stringify);
                if(signing_provider.verify(hash,  new_doc[ACU_OWNER], new_doc[ACU_SIGNATURE])) {
                  resolve(new_doc);
                } else {
                  console.log("POUCHDAC: Rejecting invalid doc",new_doc._id, new_doc[ACU_OWNER], new_doc[ACU_SIGNATURE]);
                  resolve(null);
                }
              } else {
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

  


