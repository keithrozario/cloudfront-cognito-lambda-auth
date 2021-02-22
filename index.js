// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

'use strict';
var jwt = require('jsonwebtoken');  
var jwkToPem = require('jwk-to-pem');
var config = require('./config');
var JWKS = config.JWKS;
var iss = 'https://cognito-idp.' + config.REGION + '.amazonaws.com/' + config.USERPOOLID;
var pems;

pems = {};
var keys = JSON.parse(JWKS).keys;
for(var i = 0; i < keys.length; i++) {
    var key_id = keys[i].kid;
    var modulus = keys[i].n;
    var exponent = keys[i].e;
    var key_type = keys[i].kty;
    var jwk = { kty: key_type, n: modulus, e: exponent};
    var pem = jwkToPem(jwk);
    pems[key_id] = pem;
}

const response401 = {
    status: '401',
    statusDescription: 'Unauthorized'
};

const response200 = {
    status: '200',
    statusDescription: 'Authorized'
};

exports.handler = (event, context, callback) => {
    console.log(event)
    const cfrequest = event.Records[0].cf.request;
    console.log(cfrequest)
    
    // extract JWT token only.. removin "access_token="
    
    try {
        var jwtToken = cfrequest.headers.cookie[0].value.slice(13);
    } catch (e) {
    if (e instanceof TypeError) {
            console.log("No Cookie present")
            callback(null, response401);
            return false;
    } else {
            console.log("Unknown error")
            callback(null, response401);
            return false;
        }
     }

    
    
    console.log('jwtToken= ' + jwtToken);
    var decodedJwt = jwt.decode(jwtToken, {complete: true});
    console.log("Decoded Token", decodedJwt);
    if (!decodedJwt) {
        console.log("Not a valid JWT token");
        callback(null, response401);
        return false;
    }
    
    //Get the kid from the token and retrieve corresponding PEM
    var kid = decodedJwt.header.kid;
    var pem = pems[kid];
    if (!pem) {
        console.log('Invalid access token');
        callback(null, response401);
        return false;
    }

    
    //Verify the signature of the JWT token to ensure it's really coming from your User Pool
    jwt.verify(jwtToken, pem, { issuer: iss }, function(err, payload) {
      if(err) {
        console.log('Token failed verification');
        callback(null, cfrequest);
        return true;
      } else {
        //Valid token. 
        console.log('Successful verification');
        callback(null, cfrequest);
        return true;
      }
    });
    
};