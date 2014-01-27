var util = require('util');
var crypto = require('crypto');

var async = require('async');
var request = require('request');
var concat = require('concat-stream');

var PASSWORD = "supersecret";

module.exports = verify;
function verify(baseUrl, callback) {
    var token;

    get("/list", function(err, res, body) {
        if (err) return callback(err);
        async.map(body, hashPage, withPageHashes);
    })
    function hashPage(path, next) {
        var id = /\d+/.exec(path)[0];
        var res = get(path).on('error', next);
        var md5 = crypto.createHash('md5',{encoding:'hex'}).on('error', next);
        res.pipe(md5).pipe(concat(function(hash) {
            next(null, [id, hash])
        }));
    }
    function withPageHashes(err, hashes) {
        if (err) return callback(err);
        var hasheshash = {}
        hashes.forEach(function(item) {
            hasheshash[item[0]] = item[1];
        });
        post("/verify", hasheshash, function(err, res, body) {
            callback(err, body);
        })
    }

    function get(path, done) {
        return request({
            url: baseUrl + path,
            json: true,
            headers: { 'X-Auth-Token': token }
        }, done && function(err, res, body) {
            if (err) return done(err);

            if (!token) {
                token = res.headers['x-auth-token'];
            }

            if (res.statusCode == 401) {
                return login(res.headers.location, path, done);
            }
            if (!Array.isArray(body)) {
                return done(new Error('Cannot parse json ' + body))
            }
            return done(err, res, body);
        });
    }
    function post(path, json, done) {
        request.post({
            url: baseUrl + path,
            json: json,
            headers: { 'X-Auth-Token': token }
        }, done);
    }
    function login(path, afterPath, done) {
        post(path, {password: PASSWORD}, function(err, res, body) {
            if (err) return done(err);
            if (res.statusCode != 200) {
                var msg = util.format('Login Failed: ', body);
                return done(new Error(msg));
            }
            get(afterPath, done);
        })
    }
}

if (require.main === module) {
    verify(process.env.BASE, function(err, results) {
        if (err) throw err;

        console.log("Results: ", results);
    });
}