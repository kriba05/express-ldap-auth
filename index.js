var ldap = require('ldapjs');
var Promise = require('bluebird');
var auth = require('basic-auth');

/*
HTTP/HTTPS Requests Basic Authentication and/or Authorization with LDAP. Supports JWT Based Bearer Token in header for User Authorization
1. Parse User Credentials from Authorization Header
2. Authenticate User
3. Authorize User (Optional Step) - Authorize using Ldap Roles or Authorize using roles in Bearer JWT Token
4. If user authenticated and authorized, proceed with next tick else throw error

Options Data Structure:
{
    "ldap":{
        "opts": {
            "url": "ldap://ldap.mycompany.com:389",
            "timeout":"5000"
        },
        "search":{
            "base":"",
            "filterPrefix": "",
            "filterSuffix": "",
            "opts": {
                 "scope":"sub",
                 "attributes":"memberOf"
            }
        },
        "user":{
            "DN":"",
            "attribute":"uid",
            "domain": "mycompany.com"
        }
    },
    "realm": "Basic Realm" //Optional - Default: Basic Realm
    "authorize": true/false, //Default : false
    "authorizeConfig": [    //Optional
        {
            paths: [], //Special Value: ALL
            allowedADGroups:[]
        }
    ]
}
*/

module.exports = function (opts) {
    var options = opts || {};

    return function(req, res, next) {
        var headers = req.headers;
        var authorizationHdr = headers.authorization;

        //Check if Valid Authorization Header
        if(!authorizationHdr) {
            res.setHeader('WWW-Authenticate', `Basic realm=${opts.realm}`);
            res.statusCode = 401;
            return next(new Error("User Not Authorized. Missing Authorization Header"));
        }

        var authScheme = authorizationHdr.split(' ')[0];
        if("Basic" === authScheme) {//Authenticate and/or Authorize User
            var credentials = auth(req);

            if(!credentials || !credentials.name || !credentials.pass) {
                res.setHeader('WWW-Authenticate', `Basic realm=${options.realm}`);
                res.statusCode = 401;
                return next(new Error("Invalid Authorization Header"));
            }

            var ldapClient = ldap.createClient(options.ldap.opts);
            //var user = [[options.user.attribute, credentials.name].join('='),options.user.DN].join(',');
            var user = [credentials.name,options.ldap.user.domain].join('@');//user@domain
            ldapClient.bind(user, credentials.pass, function(err) {
                if(err) {
                    res.setHeader('WWW-Authenticate', `Basic realm=${options.realm}`);
                    res.statusCode = 401;
                    return next(new Error("Authentication Failed"));
                } else if(!options.authorize) {
                    return next();
                } else {//Authorize
                        let searchFilter = options.ldap.search.filterPrefix + credentials.name + options.ldap.search.filterPrefix;
                        options.ldap.search.opts.filter = searchFilter;
                        ldapClient.search(options.ldap.search.base, options.ldap.search.opts, function(err, res) {
                            if(err) {
                                res.setHeader('WWW-Authenticate', `Basic realm=${options.realm}`);
                                res.statusCode = 401;
                                return next(new Error("Unable to Authorize User"));
                            }
                        });
                }
            });

        } else if ("Bearer" === authScheme && opts.authorize) {

        } else {
            res.setHeader('WWW-Authenticate', `Basic realm=${options.realm}`);
            res.statusCode = 401;
            return next(new Error("Unsupported Auth Scheme"));
        }
    }
}

