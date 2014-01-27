var util = require('util');
var crypto = require('crypto');

var async = require('async');
var request = require('request');
var concat = require('concat-stream');

var PASSWORD = "supersecret";

module.exports = verify;
function verify(baseUrl, num, callback) {

    var api = apiClient(createClient(baseUrl));

    async.waterfall([
        api.getList.bind(api, num),
        function(list, next) {
            async.map(list, api.getPageIdAndHash, next)
        },
        function(hasheslist, next) {
            var hashes = {}
            hasheslist.forEach(function(item) {
                hashes[item[0]] = item[1];
            });
            api.verify(hashes, next)
        }
    ], callback);
    return;
}

module.exports.apiClient = apiClient;
function apiClient(client) {
    return {
        getList: function(num, callback) {
            client.getjson("/list/" + num, function(err, res, body) {
                return callback(err, body);
            });
        },
        getPageIdAndHash: function(page, callback) {
            var id = /\d+/.exec(page)[0];
            var res = client.getstream(page, callback);

            var pipe = handle(res, crypto.createHash('md5'), callback);

            res.on('retry', function(newRes) {
                pipe.abort();
                handle(newRes, crypto.createHash('md5'), callback);
            })

            function handle(res, md5, callback) {
                res.pipe(md5).pipe(concat(function(hash) {
                    callback(null, [id, hash.toString('hex')])
                }));
                return {
                    abort: function() {
                        callback = function(){};
                    }
                }
            }
        },
        verify: function(hashes, callback) {
            client.postjson("/verify", hashes, function(err, res, body) {
                return callback(err, body);
            });
        }
    }
}

module.exports.makeClient = createClient;
function createClient(baseUrl) {
    var token;

    function getjson(path, callback) {
        makeRequest(path, {json: true}, callback);
    }
    function getstream(path, callback) {
        return makeRequest(path, {}, function(err) {
            if (err) return callback(err);
        });
    }
    function postjson(path, json, callback) {
        var options = {method: 'POST', json: json};
        makeRequest(path, options, callback);
    }

    return {
        getjson: getjson,
        getstream: getstream,
        postjson: postjson
    };

    function makeRequest(path, options, callback) {
        options.url = baseUrl + path;
        options.headers = { 'X-Auth-Token': token };

        return request(options, callback && onResponse);

        function onResponse(err, res, body) {
            err = extractError(err, options, res, body);

            // Retry once on error
            if (err && options.retried) {
                return callback(err);
            }
            if (err) {
                options.retried = true;
                var req = makeRequest(path, options, callback);
                this.emit('retry', req);
                return;
            }

            // Record token for session
            token = token || res.headers['x-auth-token'];

            // Handle missing auth
            if (res.statusCode == 401 && !options.noAutoLogin) {
                return login(res.headers.location, loginSuccess);
            }
            function loginSuccess(err) {
                if (err) return callback(err);
                makeRequest(path, options, callback);
            }

            return callback(null, res, body);
        }
    }
    function extractError(err, options, res, body) {
        if (err) return err;
        if (res.statusCode >= 500) {
            return new Error(util.format('HTTP %d:', res.statusCode, body));
        }
        if (options.json && body && (typeof body != 'object')) {
            return new Error(util.format('Inalid JSON: ', body));
        }
    }

    function login(path, callback) {
        var options = {password: PASSWORD, noAutoLogin: true};
        postjson(path, options, function(err, res, body) {
            if (err) return callback(err);
            if (res.statusCode != 200) {
                return callback(new Error(util.format('Login Failed: ', body)));
            }
            callback();
        })
    }
}

if (require.main === module) {
    var baseUrl = process.env.BASE || 'http://flaky.herokuapp.com';
    var num = process.env.NUM || 5;
    verify(baseUrl, num, function(err, results) {
        if (err) throw err;

        console.log("Results:\n", results);
    });
}
