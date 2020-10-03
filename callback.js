require = (function () {
    function r(e, n, t) {
        function o(i, f) {
            if (!n[i]) {
                if (!e[i]) {
                    var c = "function" == typeof require && require;
                    if (!f && c) return c(i, !0);
                    if (u) return u(i, !0);
                    var a = new Error("Cannot find module '" + i + "'");
                    throw a.code = "MODULE_NOT_FOUND", a
                }
                var p = n[i] = {
                    exports: {}
                };
                e[i][0].call(p.exports, function (r) {
                    var n = e[i][1][r];
                    return o(n || r)
                }, p, p.exports, r, e, n, t)
            }
            return n[i].exports
        }

        for (var u = "function" == typeof require && require, i = 0; i < t.length; i++) o(t[i]);
        return o
    }

    return r
})()({
    1: [function (require, module, exports) {
        /*!
         * cookie
         * Copyright(c) 2012-2014 Roman Shtylman
         * Copyright(c) 2015 Douglas Christopher Wilson
         * MIT Licensed
         */

        'use strict';

        /**
         * Module exports.
         * @public
         */

        exports.parse = parse;
        exports.serialize = serialize;

        /**
         * Module variables.
         * @private
         */

        var decode = decodeURIComponent;
        var encode = encodeURIComponent;
        var pairSplitRegExp = /; */;

        /**
         * RegExp to match field-content in RFC 7230 sec 3.2
         *
         * field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
         * field-vchar   = VCHAR / obs-text
         * obs-text      = %x80-FF
         */

        var fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;

        /**
         * Parse a cookie header.
         *
         * Parse the given cookie header string into an object
         * The object has the various cookies as keys(names) => values
         *
         * @param {string} str
         * @param {object} [options]
         * @return {object}
         * @public
         */

        function parse(str, options) {
            if (typeof str !== 'string') {
                throw new TypeError('argument str must be a string');
            }

            var obj = {}
            var opt = options || {};
            var pairs = str.split(pairSplitRegExp);
            var dec = opt.decode || decode;

            for (var i = 0; i < pairs.length; i++) {
                var pair = pairs[i];
                var eq_idx = pair.indexOf('=');

                // skip things that don't look like key=value
                if (eq_idx < 0) {
                    continue;
                }

                var key = pair.substr(0, eq_idx).trim()
                var val = pair.substr(++eq_idx, pair.length).trim();

                // quoted values
                if ('"' == val[0]) {
                    val = val.slice(1, -1);
                }

                // only assign once
                if (undefined == obj[key]) {
                    obj[key] = tryDecode(val, dec);
                }
            }

            return obj;
        }

        /**
         * Serialize data into a cookie header.
         *
         * Serialize the a name value pair into a cookie string suitable for
         * http headers. An optional options object specified cookie parameters.
         *
         * serialize('foo', 'bar', { httpOnly: true })
         *   => "foo=bar; httpOnly"
         *
         * @param {string} name
         * @param {string} val
         * @param {object} [options]
         * @return {string}
         * @public
         */

        function serialize(name, val, options) {
            var opt = options || {};
            var enc = opt.encode || encode;

            if (typeof enc !== 'function') {
                throw new TypeError('option encode is invalid');
            }

            if (!fieldContentRegExp.test(name)) {
                throw new TypeError('argument name is invalid');
            }

            var value = enc(val);

            if (value && !fieldContentRegExp.test(value)) {
                throw new TypeError('argument val is invalid');
            }

            var str = name + '=' + value;

            if (null != opt.maxAge) {
                var maxAge = opt.maxAge - 0;
                if (isNaN(maxAge)) throw new Error('maxAge should be a Number');
                str += '; Max-Age=' + Math.floor(maxAge);
            }

            if (opt.domain) {
                if (!fieldContentRegExp.test(opt.domain)) {
                    throw new TypeError('option domain is invalid');
                }

                str += '; Domain=' + opt.domain;
            }

            if (opt.path) {
                if (!fieldContentRegExp.test(opt.path)) {
                    throw new TypeError('option path is invalid');
                }

                str += '; Path=' + opt.path;
            }

            if (opt.expires) {
                if (typeof opt.expires.toUTCString !== 'function') {
                    throw new TypeError('option expires is invalid');
                }

                str += '; Expires=' + opt.expires.toUTCString();
            }

            if (opt.httpOnly) {
                str += '; HttpOnly';
            }

            if (opt.secure) {
                str += '; Secure';
            }

            if (opt.sameSite) {
                var sameSite = typeof opt.sameSite === 'string' ?
                    opt.sameSite.toLowerCase() : opt.sameSite;

                switch (sameSite) {
                    case true:
                        str += '; SameSite=Strict';
                        break;
                    case 'lax':
                        str += '; SameSite=Lax';
                        break;
                    case 'strict':
                        str += '; SameSite=Strict';
                        break;
                    default:
                        throw new TypeError('option sameSite is invalid');
                }
            }

            return str;
        }

        /**
         * Try decoding a string using a decoding function.
         *
         * @param {string} str
         * @param {function} decode
         * @private
         */

        function tryDecode(str, decode) {
            try {
                return decode(str);
            } catch (e) {
                return str;
            }
        }

    }, {}],
    2: [function (require, module, exports) {
        exports.OAuth = require("./lib/oauth").OAuth;
        exports.OAuthEcho = require("./lib/oauth").OAuthEcho;
        exports.OAuth2 = require("./lib/oauth2").OAuth2;
    }, {
        "./lib/oauth": 4,
        "./lib/oauth2": 5
    }],
    3: [function (require, module, exports) {
        // Returns true if this is a host that closes *before* it ends?!?!
        module.exports.isAnEarlyCloseHost = function (hostName) {
            return hostName && hostName.match(".*google(apis)?.com$")
        }
    }, {}],
    4: [function (require, module, exports) {
        var crypto = require('crypto'),
            sha1 = require('./sha1'),
            http = require('http'),
            https = require('https'),
            URL = require('url'),
            querystring = require('querystring'),
            OAuthUtils = require('./_utils');

        exports.OAuth = function (requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders) {
            this._isEcho = false;

            this._requestUrl = requestUrl;
            this._accessUrl = accessUrl;
            this._consumerKey = consumerKey;
            this._consumerSecret = this._encodeData(consumerSecret);
            if (signatureMethod == "RSA-SHA1") {
                this._privateKey = consumerSecret;
            }
            this._version = version;
            if (authorize_callback === undefined) {
                this._authorize_callback = "oob";
            } else {
                this._authorize_callback = authorize_callback;
            }

            if (signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
                throw new Error("Un-supported signature method: " + signatureMethod)
            this._signatureMethod = signatureMethod;
            this._nonceSize = nonceSize || 32;
            this._headers = customHeaders || {
                "Accept": "*/*",
                "Connection": "close",
                "User-Agent": "Node authentication"
            }
            this._clientOptions = this._defaultClientOptions = {
                "requestTokenHttpMethod": "POST",
                "accessTokenHttpMethod": "POST",
                "followRedirects": true
            };
            this._oauthParameterSeperator = ",";
        };

        exports.OAuthEcho = function (realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders) {
            this._isEcho = true;

            this._realm = realm;
            this._verifyCredentials = verify_credentials;
            this._consumerKey = consumerKey;
            this._consumerSecret = this._encodeData(consumerSecret);
            if (signatureMethod == "RSA-SHA1") {
                this._privateKey = consumerSecret;
            }
            this._version = version;

            if (signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
                throw new Error("Un-supported signature method: " + signatureMethod);
            this._signatureMethod = signatureMethod;
            this._nonceSize = nonceSize || 32;
            this._headers = customHeaders || {
                "Accept": "*/*",
                "Connection": "close",
                "User-Agent": "Node authentication"
            };
            this._oauthParameterSeperator = ",";
        }

        exports.OAuthEcho.prototype = exports.OAuth.prototype;

        exports.OAuth.prototype._getTimestamp = function () {
            return Math.floor((new Date()).getTime() / 1000);
        }

        exports.OAuth.prototype._encodeData = function (toEncode) {
            if (toEncode == null || toEncode == "") return ""
            else {
                var result = encodeURIComponent(toEncode);
                // Fix the mismatch between OAuth's  RFC3986's and Javascript's beliefs in what is right and wrong ;)
                return result.replace(/\!/g, "%21")
                    .replace(/\'/g, "%27")
                    .replace(/\(/g, "%28")
                    .replace(/\)/g, "%29")
                    .replace(/\*/g, "%2A");
            }
        }

        exports.OAuth.prototype._decodeData = function (toDecode) {
            if (toDecode != null) {
                toDecode = toDecode.replace(/\+/g, " ");
            }
            return decodeURIComponent(toDecode);
        }

        exports.OAuth.prototype._getSignature = function (method, url, parameters, tokenSecret) {
            var signatureBase = this._createSignatureBase(method, url, parameters);
            return this._createSignature(signatureBase, tokenSecret);
        }

        exports.OAuth.prototype._normalizeUrl = function (url) {
            var parsedUrl = URL.parse(url, true)
            var port = "";
            if (parsedUrl.port) {
                if ((parsedUrl.protocol == "http:" && parsedUrl.port != "80") ||
                    (parsedUrl.protocol == "https:" && parsedUrl.port != "443")) {
                    port = ":" + parsedUrl.port;
                }
            }

            if (!parsedUrl.pathname || parsedUrl.pathname == "") parsedUrl.pathname = "/";

            return parsedUrl.protocol + "//" + parsedUrl.hostname + port + parsedUrl.pathname;
        }

        // Is the parameter considered an OAuth parameter
        exports.OAuth.prototype._isParameterNameAnOAuthParameter = function (parameter) {
            var m = parameter.match('^oauth_');
            if (m && (m[0] === "oauth_")) {
                return true;
            } else {
                return false;
            }
        };

        // build the OAuth request authorization header
        exports.OAuth.prototype._buildAuthorizationHeaders = function (orderedParameters) {
            var authHeader = "OAuth ";
            if (this._isEcho) {
                authHeader += 'realm="' + this._realm + '",';
            }

            for (var i = 0; i < orderedParameters.length; i++) {
                // Whilst the all the parameters should be included within the signature, only the oauth_ arguments
                // should appear within the authorization header.
                if (this._isParameterNameAnOAuthParameter(orderedParameters[i][0])) {
                    authHeader += "" + this._encodeData(orderedParameters[i][0]) + "=\"" + this._encodeData(orderedParameters[i][1]) + "\"" + this._oauthParameterSeperator;
                }
            }

            authHeader = authHeader.substring(0, authHeader.length - this._oauthParameterSeperator.length);
            return authHeader;
        }

        // Takes an object literal that represents the arguments, and returns an array
        // of argument/value pairs.
        exports.OAuth.prototype._makeArrayOfArgumentsHash = function (argumentsHash) {
            var argument_pairs = [];
            for (var key in argumentsHash) {
                if (argumentsHash.hasOwnProperty(key)) {
                    var value = argumentsHash[key];
                    if (Array.isArray(value)) {
                        for (var i = 0; i < value.length; i++) {
                            argument_pairs[argument_pairs.length] = [key, value[i]];
                        }
                    } else {
                        argument_pairs[argument_pairs.length] = [key, value];
                    }
                }
            }
            return argument_pairs;
        }

        // Sorts the encoded key value pairs by encoded name, then encoded value
        exports.OAuth.prototype._sortRequestParams = function (argument_pairs) {
            // Sort by name, then value.
            argument_pairs.sort(function (a, b) {
                if (a[0] == b[0]) {
                    return a[1] < b[1] ? -1 : 1;
                } else return a[0] < b[0] ? -1 : 1;
            });

            return argument_pairs;
        }

        exports.OAuth.prototype._normaliseRequestParams = function (args) {
            var argument_pairs = this._makeArrayOfArgumentsHash(args);
            // First encode them #3.4.1.3.2 .1
            for (var i = 0; i < argument_pairs.length; i++) {
                argument_pairs[i][0] = this._encodeData(argument_pairs[i][0]);
                argument_pairs[i][1] = this._encodeData(argument_pairs[i][1]);
            }

            // Then sort them #3.4.1.3.2 .2
            argument_pairs = this._sortRequestParams(argument_pairs);

            // Then concatenate together #3.4.1.3.2 .3 & .4
            var args = "";
            for (var i = 0; i < argument_pairs.length; i++) {
                args += argument_pairs[i][0];
                args += "="
                args += argument_pairs[i][1];
                if (i < argument_pairs.length - 1) args += "&";
            }
            return args;
        }

        exports.OAuth.prototype._createSignatureBase = function (method, url, parameters) {
            url = this._encodeData(this._normalizeUrl(url));
            parameters = this._encodeData(parameters);
            return method.toUpperCase() + "&" + url + "&" + parameters;
        }

        exports.OAuth.prototype._createSignature = function (signatureBase, tokenSecret) {
            if (tokenSecret === undefined) var tokenSecret = "";
            else tokenSecret = this._encodeData(tokenSecret);
            // consumerSecret is already encoded
            var key = this._consumerSecret + "&" + tokenSecret;

            var hash = ""
            if (this._signatureMethod == "PLAINTEXT") {
                hash = key;
            } else if (this._signatureMethod == "RSA-SHA1") {
                key = this._privateKey || "";
                hash = crypto.createSign("RSA-SHA1").update(signatureBase).sign(key, 'base64');
            } else {
                if (crypto.Hmac) {
                    hash = crypto.createHmac("sha1", key).update(signatureBase).digest("base64");
                } else {
                    hash = sha1.HMACSHA1(key, signatureBase);
                }
            }
            return hash;
        }
        exports.OAuth.prototype.NONCE_CHARS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
            'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3',
            '4', '5', '6', '7', '8', '9'
        ];

        exports.OAuth.prototype._getNonce = function (nonceSize) {
            var result = [];
            var chars = this.NONCE_CHARS;
            var char_pos;
            var nonce_chars_length = chars.length;

            for (var i = 0; i < nonceSize; i++) {
                char_pos = Math.floor(Math.random() * nonce_chars_length);
                result[i] = chars[char_pos];
            }
            return result.join('');
        }

        exports.OAuth.prototype._createClient = function (port, hostname, method, path, headers, sslEnabled) {
            var options = {
                host: hostname,
                port: port,
                path: path,
                method: method,
                headers: headers
            };
            var httpModel;
            if (sslEnabled) {
                httpModel = https;
            } else {
                httpModel = http;
            }
            return httpModel.request(options);
        }

        exports.OAuth.prototype._prepareParameters = function (oauth_token, oauth_token_secret, method, url, extra_params) {
            var oauthParameters = {
                "oauth_timestamp": this._getTimestamp(),
                "oauth_nonce": this._getNonce(this._nonceSize),
                "oauth_version": this._version,
                "oauth_signature_method": this._signatureMethod,
                "oauth_consumer_key": this._consumerKey
            };

            if (oauth_token) {
                oauthParameters["oauth_token"] = oauth_token;
            }

            var sig;
            if (this._isEcho) {
                sig = this._getSignature("GET", this._verifyCredentials, this._normaliseRequestParams(oauthParameters), oauth_token_secret);
            } else {
                if (extra_params) {
                    for (var key in extra_params) {
                        if (extra_params.hasOwnProperty(key)) oauthParameters[key] = extra_params[key];
                    }
                }
                var parsedUrl = URL.parse(url, false);

                if (parsedUrl.query) {
                    var key2;
                    var extraParameters = querystring.parse(parsedUrl.query);
                    for (var key in extraParameters) {
                        var value = extraParameters[key];
                        if (typeof value == "object") {
                            // TODO: This probably should be recursive
                            for (key2 in value) {
                                oauthParameters[key + "[" + key2 + "]"] = value[key2];
                            }
                        } else {
                            oauthParameters[key] = value;
                        }
                    }
                }

                sig = this._getSignature(method, url, this._normaliseRequestParams(oauthParameters), oauth_token_secret);
            }

            var orderedParameters = this._sortRequestParams(this._makeArrayOfArgumentsHash(oauthParameters));
            orderedParameters[orderedParameters.length] = ["oauth_signature", sig];
            return orderedParameters;
        }

        exports.OAuth.prototype._performSecureRequest = function (oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type, callback) {
            var orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, extra_params);

            if (!post_content_type) {
                post_content_type = "application/x-www-form-urlencoded";
            }
            var parsedUrl = URL.parse(url, false);
            if (parsedUrl.protocol == "http:" && !parsedUrl.port) parsedUrl.port = 80;
            if (parsedUrl.protocol == "https:" && !parsedUrl.port) parsedUrl.port = 443;

            var headers = {};
            var authorization = this._buildAuthorizationHeaders(orderedParameters);
            if (this._isEcho) {
                headers["X-Verify-Credentials-Authorization"] = authorization;
            } else {
                headers["Authorization"] = authorization;
            }

            headers["Host"] = parsedUrl.host

            for (var key in this._headers) {
                if (this._headers.hasOwnProperty(key)) {
                    headers[key] = this._headers[key];
                }
            }

            // Filter out any passed extra_params that are really to do with OAuth
            for (var key in extra_params) {
                if (this._isParameterNameAnOAuthParameter(key)) {
                    delete extra_params[key];
                }
            }

            if ((method == "POST" || method == "PUT") && (post_body == null && extra_params != null)) {
                // Fix the mismatch between the output of querystring.stringify() and this._encodeData()
                post_body = querystring.stringify(extra_params)
                    .replace(/\!/g, "%21")
                    .replace(/\'/g, "%27")
                    .replace(/\(/g, "%28")
                    .replace(/\)/g, "%29")
                    .replace(/\*/g, "%2A");
            }

            if (post_body) {
                if (Buffer.isBuffer(post_body)) {
                    headers["Content-length"] = post_body.length;
                } else {
                    headers["Content-length"] = Buffer.byteLength(post_body);
                }
            } else {
                headers["Content-length"] = 0;
            }

            headers["Content-Type"] = post_content_type;

            var path;
            if (!parsedUrl.pathname || parsedUrl.pathname == "") parsedUrl.pathname = "/";
            if (parsedUrl.query) path = parsedUrl.pathname + "?" + parsedUrl.query;
            else path = parsedUrl.pathname;

            var request;
            if (parsedUrl.protocol == "https:") {
                request = this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers, true);
            } else {
                request = this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers);
            }

            var clientOptions = this._clientOptions;
            if (callback) {
                var data = "";
                var self = this;

                // Some hosts *cough* google appear to close the connection early / send no content-length header
                // allow this behaviour.
                var allowEarlyClose = OAuthUtils.isAnEarlyCloseHost(parsedUrl.hostname);
                var callbackCalled = false;
                var passBackControl = function (response) {
                    if (!callbackCalled) {
                        callbackCalled = true;
                        if (response.statusCode >= 200 && response.statusCode <= 299) {
                            callback(null, data, response);
                        } else {
                            // Follow 301 or 302 redirects with Location HTTP header
                            if ((response.statusCode == 301 || response.statusCode == 302) && clientOptions.followRedirects && response.headers && response.headers.location) {
                                self._performSecureRequest(oauth_token, oauth_token_secret, method, response.headers.location, extra_params, post_body, post_content_type, callback);
                            } else {
                                callback({
                                    statusCode: response.statusCode,
                                    data: data
                                }, data, response);
                            }
                        }
                    }
                }

                request.on('response', function (response) {
                    response.setEncoding('utf8');
                    response.on('data', function (chunk) {
                        data += chunk;
                    });
                    response.on('end', function () {
                        passBackControl(response);
                    });
                    response.on('close', function () {
                        if (allowEarlyClose) {
                            passBackControl(response);
                        }
                    });
                });

                request.on("error", function (err) {
                    if (!callbackCalled) {
                        callbackCalled = true;
                        callback(err)
                    }
                });

                if ((method == "POST" || method == "PUT") && post_body != null && post_body != "") {
                    request.write(post_body);
                }
                request.end();
            } else {
                if ((method == "POST" || method == "PUT") && post_body != null && post_body != "") {
                    request.write(post_body);
                }
                return request;
            }

            return;
        }

        exports.OAuth.prototype.setClientOptions = function (options) {
            var key,
                mergedOptions = {},
                hasOwnProperty = Object.prototype.hasOwnProperty;

            for (key in this._defaultClientOptions) {
                if (!hasOwnProperty.call(options, key)) {
                    mergedOptions[key] = this._defaultClientOptions[key];
                } else {
                    mergedOptions[key] = options[key];
                }
            }

            this._clientOptions = mergedOptions;
        };

        exports.OAuth.prototype.getOAuthAccessToken = function (oauth_token, oauth_token_secret, oauth_verifier, callback) {
            var extraParams = {};
            if (typeof oauth_verifier == "function") {
                callback = oauth_verifier;
            } else {
                extraParams.oauth_verifier = oauth_verifier;
            }

            this._performSecureRequest(oauth_token, oauth_token_secret, this._clientOptions.accessTokenHttpMethod, this._accessUrl, extraParams, null, null, function (error, data, response) {
                if (error) callback(error);
                else {
                    var results = querystring.parse(data);
                    var oauth_access_token = results["oauth_token"];
                    delete results["oauth_token"];
                    var oauth_access_token_secret = results["oauth_token_secret"];
                    delete results["oauth_token_secret"];
                    callback(null, oauth_access_token, oauth_access_token_secret, results);
                }
            })
        }

        // Deprecated
        exports.OAuth.prototype.getProtectedResource = function (url, method, oauth_token, oauth_token_secret, callback) {
            this._performSecureRequest(oauth_token, oauth_token_secret, method, url, null, "", null, callback);
        }

        exports.OAuth.prototype.delete = function (url, oauth_token, oauth_token_secret, callback) {
            return this._performSecureRequest(oauth_token, oauth_token_secret, "DELETE", url, null, "", null, callback);
        }

        exports.OAuth.prototype.get = function (url, oauth_token, oauth_token_secret, callback) {
            return this._performSecureRequest(oauth_token, oauth_token_secret, "GET", url, null, "", null, callback);
        }

        exports.OAuth.prototype._putOrPost = function (method, url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
            var extra_params = null;
            if (typeof post_content_type == "function") {
                callback = post_content_type;
                post_content_type = null;
            }
            if (typeof post_body != "string" && !Buffer.isBuffer(post_body)) {
                post_content_type = "application/x-www-form-urlencoded"
                extra_params = post_body;
                post_body = null;
            }
            return this._performSecureRequest(oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type, callback);
        }


        exports.OAuth.prototype.put = function (url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
            return this._putOrPost("PUT", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
        }

        exports.OAuth.prototype.post = function (url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
            return this._putOrPost("POST", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
        }

        /**
         * Gets a request token from the OAuth provider and passes that information back
         * to the calling code.
         *
         * The callback should expect a function of the following form:
         *
         * function(err, token, token_secret, parsedQueryString) {}
         *
         * This method has optional parameters so can be called in the following 2 ways:
         *
         * 1) Primary use case: Does a basic request with no extra parameters
         *  getOAuthRequestToken( callbackFunction )
         *
         * 2) As above but allows for provision of extra parameters to be sent as part of the query to the server.
         *  getOAuthRequestToken( extraParams, callbackFunction )
         *
         * N.B. This method will HTTP POST verbs by default, if you wish to override this behaviour you will
         * need to provide a requestTokenHttpMethod option when creating the client.
         *
         **/
        exports.OAuth.prototype.getOAuthRequestToken = function (extraParams, callback) {
            if (typeof extraParams == "function") {
                callback = extraParams;
                extraParams = {};
            }
            // Callbacks are 1.0A related
            if (this._authorize_callback) {
                extraParams["oauth_callback"] = this._authorize_callback;
            }
            this._performSecureRequest(null, null, this._clientOptions.requestTokenHttpMethod, this._requestUrl, extraParams, null, null, function (error, data, response) {
                if (error) callback(error);
                else {
                    var results = querystring.parse(data);

                    var oauth_token = results["oauth_token"];
                    var oauth_token_secret = results["oauth_token_secret"];
                    delete results["oauth_token"];
                    delete results["oauth_token_secret"];
                    callback(null, oauth_token, oauth_token_secret, results);
                }
            });
        }

        exports.OAuth.prototype.signUrl = function (url, oauth_token, oauth_token_secret, method) {

            if (method === undefined) {
                var method = "GET";
            }

            var orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
            var parsedUrl = URL.parse(url, false);

            var query = "";
            for (var i = 0; i < orderedParameters.length; i++) {
                query += orderedParameters[i][0] + "=" + this._encodeData(orderedParameters[i][1]) + "&";
            }
            query = query.substring(0, query.length - 1);

            return parsedUrl.protocol + "//" + parsedUrl.host + parsedUrl.pathname + "?" + query;
        };

        exports.OAuth.prototype.authHeader = function (url, oauth_token, oauth_token_secret, method) {
            if (method === undefined) {
                var method = "GET";
            }

            var orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
            return this._buildAuthorizationHeaders(orderedParameters);
        };

    }, {
        "./_utils": 3,
        "./sha1": 6,
        "crypto": undefined,
        "http": undefined,
        "https": undefined,
        "querystring": undefined,
        "url": undefined
    }],
    5: [function (require, module, exports) {
        var querystring = require('querystring'),
            crypto = require('crypto'),
            https = require('https'),
            http = require('http'),
            URL = require('url'),
            OAuthUtils = require('./_utils');

        exports.OAuth2 = function (clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
            this._clientId = clientId;
            this._clientSecret = clientSecret;
            this._baseSite = baseSite;
            this._authorizeUrl = authorizePath || "/oauth/authorize";
            this._accessTokenUrl = accessTokenPath || "/oauth/access_token";
            this._accessTokenName = "access_token";
            this._authMethod = "Bearer";
            this._customHeaders = customHeaders || {};
            this._useAuthorizationHeaderForGET = false;

            //our agent
            this._agent = undefined;
        };

        // Allows you to set an agent to use instead of the default HTTP or
        // HTTPS agents. Useful when dealing with your own certificates.
        exports.OAuth2.prototype.setAgent = function (agent) {
            this._agent = agent;
        };

        // This 'hack' method is required for sites that don't use
        // 'access_token' as the name of the access token (for requests).
        // ( http://tools.ietf.org/html/draft-ietf-oauth-v2-16#section-7 )
        // it isn't clear what the correct value should be atm, so allowing
        // for specific (temporary?) override for now.
        exports.OAuth2.prototype.setAccessTokenName = function (name) {
            this._accessTokenName = name;
        }

        // Sets the authorization method for Authorization header.
        // e.g. Authorization: Bearer <token>  # "Bearer" is the authorization method.
        exports.OAuth2.prototype.setAuthMethod = function (authMethod) {
            this._authMethod = authMethod;
        };


        // If you use the OAuth2 exposed 'get' method (and don't construct your own _request call )
        // this will specify whether to use an 'Authorize' header instead of passing the access_token as a query parameter
        exports.OAuth2.prototype.useAuthorizationHeaderforGET = function (useIt) {
            this._useAuthorizationHeaderForGET = useIt;
        }

        exports.OAuth2.prototype._getAccessTokenUrl = function () {
            return this._baseSite + this._accessTokenUrl;
            /* + "?" + querystring.stringify(params); */
        }

        // Build the authorization header. In particular, build the part after the colon.
        // e.g. Authorization: Bearer <token>  # Build "Bearer <token>"
        exports.OAuth2.prototype.buildAuthHeader = function (token) {
            return this._authMethod + ' ' + token;
        };

        exports.OAuth2.prototype._chooseHttpLibrary = function (parsedUrl) {
            var http_library = https;
            // As this is OAUth2, we *assume* https unless told explicitly otherwise.
            if (parsedUrl.protocol != "https:") {
                http_library = http;
            }
            return http_library;
        };

        exports.OAuth2.prototype._request = function (method, url, headers, post_body, access_token, callback) {

            var parsedUrl = URL.parse(url, true);
            if (parsedUrl.protocol == "https:" && !parsedUrl.port) {
                parsedUrl.port = 443;
            }

            var http_library = this._chooseHttpLibrary(parsedUrl);


            var realHeaders = {};
            for (var key in this._customHeaders) {
                realHeaders[key] = this._customHeaders[key];
            }
            if (headers) {
                for (var key in headers) {
                    realHeaders[key] = headers[key];
                }
            }
            realHeaders['Host'] = parsedUrl.host;

            if (!realHeaders['User-Agent']) {
                realHeaders['User-Agent'] = 'Node-oauth';
            }

            if (post_body) {
                if (Buffer.isBuffer(post_body)) {
                    realHeaders["Content-Length"] = post_body.length;
                } else {
                    realHeaders["Content-Length"] = Buffer.byteLength(post_body);
                }
            } else {
                realHeaders["Content-length"] = 0;
            }

            if (access_token && !('Authorization' in realHeaders)) {
                if (!parsedUrl.query) parsedUrl.query = {};
                parsedUrl.query[this._accessTokenName] = access_token;
            }

            var queryStr = querystring.stringify(parsedUrl.query);
            if (queryStr) queryStr = "?" + queryStr;
            var options = {
                host: parsedUrl.hostname,
                port: parsedUrl.port,
                path: parsedUrl.pathname + queryStr,
                method: method,
                headers: realHeaders
            };

            this._executeRequest(http_library, options, post_body, callback);
        }

        exports.OAuth2.prototype._executeRequest = function (http_library, options, post_body, callback) {
            // Some hosts *cough* google appear to close the connection early / send no content-length header
            // allow this behaviour.
            var allowEarlyClose = OAuthUtils.isAnEarlyCloseHost(options.host);
            var callbackCalled = false;

            function passBackControl(response, result) {
                if (!callbackCalled) {
                    callbackCalled = true;
                    if (!(response.statusCode >= 200 && response.statusCode <= 299) && (response.statusCode != 301) && (response.statusCode != 302)) {
                        callback({
                            statusCode: response.statusCode,
                            data: result
                        });
                    } else {
                        callback(null, result, response);
                    }
                }
            }

            var result = "";

            //set the agent on the request options
            if (this._agent) {
                options.agent = this._agent;
            }

            var request = http_library.request(options);
            request.on('response', function (response) {
                response.on("data", function (chunk) {
                    result += chunk
                });
                response.on("close", function (err) {
                    if (allowEarlyClose) {
                        passBackControl(response, result);
                    }
                });
                response.addListener("end", function () {
                    passBackControl(response, result);
                });
            });
            request.on('error', function (e) {
                callbackCalled = true;
                callback(e);
            });

            if ((options.method == 'POST' || options.method == 'PUT') && post_body) {
                request.write(post_body);
            }
            request.end();
        }

        exports.OAuth2.prototype.getAuthorizeUrl = function (params) {
            var params = params || {};
            params['client_id'] = this._clientId;
            return this._baseSite + this._authorizeUrl + "?" + querystring.stringify(params);
        }

        exports.OAuth2.prototype.getOAuthAccessToken = function (code, params, callback) {
            var params = params || {};
            params['client_id'] = this._clientId;
            params['client_secret'] = this._clientSecret;
            var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
            params[codeParam] = code;

            var post_data = querystring.stringify(params);
            var post_headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            };


            this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function (error, data, response) {
                if (error) callback(error);
                else {
                    var results;
                    try {
                        // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
                        // responses should be in JSON
                        results = JSON.parse(data);
                    } catch (e) {
                        // .... However both Facebook + Github currently use rev05 of the spec
                        // and neither seem to specify a content-type correctly in their response headers :(
                        // clients of these services will suffer a *minor* performance cost of the exception
                        // being thrown
                        results = querystring.parse(data);
                    }
                    var access_token = results["access_token"];
                    var refresh_token = results["refresh_token"];
                    delete results["refresh_token"];
                    callback(null, access_token, refresh_token, results); // callback results =-=
                }
            });
        }

        // Deprecated
        exports.OAuth2.prototype.getProtectedResource = function (url, access_token, callback) {
            this._request("GET", url, {}, "", access_token, callback);
        }

        exports.OAuth2.prototype.get = function (url, access_token, callback) {
            if (this._useAuthorizationHeaderForGET) {
                var headers = {
                    'Authorization': this.buildAuthHeader(access_token)
                }
                access_token = null;
            } else {
                headers = {};
            }
            this._request("GET", url, headers, "", access_token, callback);
        }

    }, {
        "./_utils": 3,
        "crypto": undefined,
        "http": undefined,
        "https": undefined,
        "querystring": undefined,
        "url": undefined
    }],
    6: [function (require, module, exports) {
        /*
         * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
         * in FIPS 180-1
         * Version 2.2 Copyright Paul Johnston 2000 - 2009.
         * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
         * Distributed under the BSD License
         * See http://pajhome.org.uk/crypt/md5 for details.
         */

        /*
         * Configurable variables. You may need to tweak these to be compatible with
         * the server-side, but the defaults work in most cases.
         */
        var hexcase = 1;
        /* hex output format. 0 - lowercase; 1 - uppercase        */
        var b64pad = "=";
        /* base-64 pad character. "=" for strict RFC compliance   */

        /*
         * These are the functions you'll usually want to call
         * They take string arguments and return either hex or base-64 encoded strings
         */
        function hex_sha1(s) {
            return rstr2hex(rstr_sha1(str2rstr_utf8(s)));
        }

        function b64_sha1(s) {
            return rstr2b64(rstr_sha1(str2rstr_utf8(s)));
        }

        function any_sha1(s, e) {
            return rstr2any(rstr_sha1(str2rstr_utf8(s)), e);
        }

        function hex_hmac_sha1(k, d) {
            return rstr2hex(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d)));
        }

        function b64_hmac_sha1(k, d) {
            return rstr2b64(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d)));
        }

        function any_hmac_sha1(k, d, e) {
            return rstr2any(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d)), e);
        }

        /*
         * Perform a simple self-test to see if the VM is working
         */
        function sha1_vm_test() {
            return hex_sha1("abc").toLowerCase() == "a9993e364706816aba3e25717850c26c9cd0d89d";
        }

        /*
         * Calculate the SHA1 of a raw string
         */
        function rstr_sha1(s) {
            return binb2rstr(binb_sha1(rstr2binb(s), s.length * 8));
        }

        /*
         * Calculate the HMAC-SHA1 of a key and some data (raw strings)
         */
        function rstr_hmac_sha1(key, data) {
            var bkey = rstr2binb(key);
            if (bkey.length > 16) bkey = binb_sha1(bkey, key.length * 8);

            var ipad = Array(16),
                opad = Array(16);
            for (var i = 0; i < 16; i++) {
                ipad[i] = bkey[i] ^ 0x36363636;
                opad[i] = bkey[i] ^ 0x5C5C5C5C;
            }

            var hash = binb_sha1(ipad.concat(rstr2binb(data)), 512 + data.length * 8);
            return binb2rstr(binb_sha1(opad.concat(hash), 512 + 160));
        }

        /*
         * Convert a raw string to a hex string
         */
        function rstr2hex(input) {
            try {
                hexcase
            } catch (e) {
                hexcase = 0;
            }
            var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
            var output = "";
            var x;
            for (var i = 0; i < input.length; i++) {
                x = input.charCodeAt(i);
                output += hex_tab.charAt((x >>> 4) & 0x0F) +
                    hex_tab.charAt(x & 0x0F);
            }
            return output;
        }

        /*
         * Convert a raw string to a base-64 string
         */
        function rstr2b64(input) {
            try {
                b64pad
            } catch (e) {
                b64pad = '';
            }
            var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            var output = "";
            var len = input.length;
            for (var i = 0; i < len; i += 3) {
                var triplet = (input.charCodeAt(i) << 16) |
                    (i + 1 < len ? input.charCodeAt(i + 1) << 8 : 0) |
                    (i + 2 < len ? input.charCodeAt(i + 2) : 0);
                for (var j = 0; j < 4; j++) {
                    if (i * 8 + j * 6 > input.length * 8) output += b64pad;
                    else output += tab.charAt((triplet >>> 6 * (3 - j)) & 0x3F);
                }
            }
            return output;
        }

        /*
         * Convert a raw string to an arbitrary string encoding
         */
        function rstr2any(input, encoding) {
            var divisor = encoding.length;
            var remainders = Array();
            var i, q, x, quotient;

            /* Convert to an array of 16-bit big-endian values, forming the dividend */
            var dividend = Array(Math.ceil(input.length / 2));
            for (i = 0; i < dividend.length; i++) {
                dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
            }

            /*
             * Repeatedly perform a long division. The binary array forms the dividend,
             * the length of the encoding is the divisor. Once computed, the quotient
             * forms the dividend for the next step. We stop when the dividend is zero.
             * All remainders are stored for later use.
             */
            while (dividend.length > 0) {
                quotient = Array();
                x = 0;
                for (i = 0; i < dividend.length; i++) {
                    x = (x << 16) + dividend[i];
                    q = Math.floor(x / divisor);
                    x -= q * divisor;
                    if (quotient.length > 0 || q > 0)
                        quotient[quotient.length] = q;
                }
                remainders[remainders.length] = x;
                dividend = quotient;
            }

            /* Convert the remainders to the output string */
            var output = "";
            for (i = remainders.length - 1; i >= 0; i--)
                output += encoding.charAt(remainders[i]);

            /* Append leading zero equivalents */
            var full_length = Math.ceil(input.length * 8 /
                (Math.log(encoding.length) / Math.log(2)))
            for (i = output.length; i < full_length; i++)
                output = encoding[0] + output;

            return output;
        }

        /*
         * Encode a string as utf-8.
         * For efficiency, this assumes the input is valid utf-16.
         */
        function str2rstr_utf8(input) {
            var output = "";
            var i = -1;
            var x, y;

            while (++i < input.length) {
                /* Decode utf-16 surrogate pairs */
                x = input.charCodeAt(i);
                y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
                if (0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF) {
                    x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
                    i++;
                }

                /* Encode output as utf-8 */
                if (x <= 0x7F)
                    output += String.fromCharCode(x);
                else if (x <= 0x7FF)
                    output += String.fromCharCode(0xC0 | ((x >>> 6) & 0x1F),
                        0x80 | (x & 0x3F));
                else if (x <= 0xFFFF)
                    output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                        0x80 | ((x >>> 6) & 0x3F),
                        0x80 | (x & 0x3F));
                else if (x <= 0x1FFFFF)
                    output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                        0x80 | ((x >>> 12) & 0x3F),
                        0x80 | ((x >>> 6) & 0x3F),
                        0x80 | (x & 0x3F));
            }
            return output;
        }

        /*
         * Encode a string as utf-16
         */
        function str2rstr_utf16le(input) {
            var output = "";
            for (var i = 0; i < input.length; i++)
                output += String.fromCharCode(input.charCodeAt(i) & 0xFF,
                    (input.charCodeAt(i) >>> 8) & 0xFF);
            return output;
        }

        function str2rstr_utf16be(input) {
            var output = "";
            for (var i = 0; i < input.length; i++)
                output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
                    input.charCodeAt(i) & 0xFF);
            return output;
        }

        /*
         * Convert a raw string to an array of big-endian words
         * Characters >255 have their high-byte silently ignored.
         */
        function rstr2binb(input) {
            var output = Array(input.length >> 2);
            for (var i = 0; i < output.length; i++)
                output[i] = 0;
            for (var i = 0; i < input.length * 8; i += 8)
                output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
            return output;
        }

        /*
         * Convert an array of big-endian words to a string
         */
        function binb2rstr(input) {
            var output = "";
            for (var i = 0; i < input.length * 32; i += 8)
                output += String.fromCharCode((input[i >> 5] >>> (24 - i % 32)) & 0xFF);
            return output;
        }

        /*
         * Calculate the SHA-1 of an array of big-endian words, and a bit length
         */
        function binb_sha1(x, len) {
            /* append padding */
            x[len >> 5] |= 0x80 << (24 - len % 32);
            x[((len + 64 >> 9) << 4) + 15] = len;

            var w = Array(80);
            var a = 1732584193;
            var b = -271733879;
            var c = -1732584194;
            var d = 271733878;
            var e = -1009589776;

            for (var i = 0; i < x.length; i += 16) {
                var olda = a;
                var oldb = b;
                var oldc = c;
                var oldd = d;
                var olde = e;

                for (var j = 0; j < 80; j++) {
                    if (j < 16) w[j] = x[i + j];
                    else w[j] = bit_rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
                    var t = safe_add(safe_add(bit_rol(a, 5), sha1_ft(j, b, c, d)),
                        safe_add(safe_add(e, w[j]), sha1_kt(j)));
                    e = d;
                    d = c;
                    c = bit_rol(b, 30);
                    b = a;
                    a = t;
                }

                a = safe_add(a, olda);
                b = safe_add(b, oldb);
                c = safe_add(c, oldc);
                d = safe_add(d, oldd);
                e = safe_add(e, olde);
            }
            return Array(a, b, c, d, e);

        }

        /*
         * Perform the appropriate triplet combination function for the current
         * iteration
         */
        function sha1_ft(t, b, c, d) {
            if (t < 20) return (b & c) | ((~b) & d);
            if (t < 40) return b ^ c ^ d;
            if (t < 60) return (b & c) | (b & d) | (c & d);
            return b ^ c ^ d;
        }

        /*
         * Determine the appropriate additive constant for the current iteration
         */
        function sha1_kt(t) {
            return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 :
                (t < 60) ? -1894007588 : -899497514;
        }

        /*
         * Add integers, wrapping at 2^32. This uses 16-bit operations internally
         * to work around bugs in some JS interpreters.
         */
        function safe_add(x, y) {
            var lsw = (x & 0xFFFF) + (y & 0xFFFF);
            var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
            return (msw << 16) | (lsw & 0xFFFF);
        }

        /*
         * Bitwise rotate a 32-bit number to the left.
         */
        function bit_rol(num, cnt) {
            return (num << cnt) | (num >>> (32 - cnt));
        }

        exports.HMACSHA1 = function (key, data) {
            return b64_hmac_sha1(key, data);
        }
    }, {}],
    7: [function (require, module, exports) {
        /**
         Copyright (c) 2014 - present Adobe Systems Incorporated. All rights reserved.

         Licensed under the Apache License, Version 2.0 (the "License");
         you may not use this file except in compliance with the License.
         You may obtain a copy of the License at

         http://www.apache.org/licenses/LICENSE-2.0

         Unless required by applicable law or agreed to in writing, software
         distributed under the License is distributed on an "AS IS" BASIS,
         WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
         See the License for the specific language governing permissions and
         limitations under the License.
         */

        /**
         * Module dependencies.
         */
        var Strategy = require('./strategy');

        /**
         * Framework version.
         */
        // removed pkginfo ...')(module, 'version');

        /**
         * Expose constructors.
         */
        exports.Strategy = Strategy;

    }, {
        "./strategy": 8,
        "pkginfo": 34
    }],
    8: [function (require, module, exports) {
        /**
         Copyright (c) 2014 - present Adobe Systems Incorporated. All rights reserved.

         Licensed under the Apache License, Version 2.0 (the "License");
         you may not use this file except in compliance with the License.
         You may obtain a copy of the License at

         http://www.apache.org/licenses/LICENSE-2.0

         Unless required by applicable law or agreed to in writing, software
         distributed under the License is distributed on an "AS IS" BASIS,
         WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
         See the License for the specific language governing permissions and
         limitations under the License.
         */

        /**
         * Module dependencies.
         */
        var util = require('util');
        var PassportOAuth = require('passport-oauth');


        /**
         * `Strategy` constructor.
         *
         * The Adobe authentication strategy authenticates requests by delegating to
         * Adobe using the OAuth 2.0 protocol.
         *
         * Applications must supply a `request_uri` callback which accepts an `access_token`,
         * `expires_in`, `token_type` and service-specific `profile`, and then calls the `done`
         * callback supplying a `user`, which should be set to `false` if the
         * credentials are not valid.  If an exception occured, `err` should be set.
         *
         * Options:
         *   - `clientID`      your Adobe application's app key
         *   - `clientSecret`  your Adobe application's app secret
         *   - `callbackURL`   URL to which Adobe will redirect the user after granting authorization
         *
         * Examples:
         *
         *     passport.use(new AdobeStrategy({
         *         clientID: 'yourAppKey',
         *         clientSecret: 'yourAppSecret'
         *         callbackURL: 'https://www.example.net/auth/adobe-oauth2/callback',
         *         response_type: 'token'
         *       },
         *       function(access_token, expires_in, token_type, profile, done) {
         *         User.findOrCreate(..., function (err, user) {
         *           done(err, user);
         *         });
         *       }
         *     ));
         *
         * @param {Object} options
         * @param {Function} verify
         * @api public
         */
        function Strategy(options, verify) {
            var opts = options || {};
            opts.authorizationEndpoint = opts.authorizationEndpoint || 'https://ims-na1.adobelogin.com';
            opts.authorizationURL = opts.authorizationURL || opts.authorizationEndpoint + '/ims/authorize/v1';
            opts.tokenURL = opts.tokenURL || opts.authorizationEndpoint + '/ims/token/v1';
            opts.profileURL = opts.profileURL || opts.authorizationEndpoint + '/ims/profile/v1';
            opts.scopeSeparator = opts.scopeSeparator || ',';
            opts.customHeaders = opts.customHeaders || {};
            PassportOAuth.OAuth2Strategy.call(this, opts, verify);
            this.name = 'adobe';
            this._clientID = opts.clientID;
            this._profileURL = opts.profileURL;
        }

        /**
         * Inherit from `PassportOAuth.OAuth2Strategy`.
         */
        util.inherits(Strategy, PassportOAuth.OAuth2Strategy);

        Strategy.prototype.authorizationParams = function authorizationParams(/* options */) {
            var params = {};
            // params.response_type="token";
            return params;
        };


        /**
         * Retrieve user profile from Adobe.
         *
         * This function constructs a normalized profile, with the following properties:
         *
         *   - `provider`         always set to `adobe`
         *   - `id`               the user's Adobe ID
         *   - `username`         the user's Adobe username
         *   - `displayName`      the user's full name
         *   - `profileUrl`       the URL of the profile for the user on Adobe
         *   - `emails`           the user's email addresses
         *
         * @param {String} accessToken
         * @param {Function} done
         * @api protected
         */
        Strategy.prototype.userProfile = function (accessToken, done) {
            this._oauth2.useAuthorizationHeaderforGET(true);
            this._oauth2.get(this._profileURL + '?client_id=' + this._clientID, accessToken,
                function (err, body /* , res */) {
                    if (err) {
                        return done(new PassportOAuth.InternalOAuthError('failed to fetch user profile', err));
                    }

                    try {
                        var json = JSON.parse(body);

                        var profile = {
                            provider: 'adobe'
                        };
                        profile.id = json.userId;
                        profile.displayName = json.displayName;
                        profile.emails = [{
                            value: json.email
                        }];

                        profile._raw = body;
                        profile._json = json;

                        done(null, profile);
                    } catch (e) {
                        done(e);
                    }
                });
        }


        /**
         * Expose `Strategy`.
         */
        module.exports = Strategy;

    }, {
        "passport-oauth": 9,
        "util": undefined
    }],
    9: [function (require, module, exports) {
        /**
         * Module dependencies.
         */
        var OAuthStrategy = require('passport-oauth1'),
            OAuth2Strategy = require('passport-oauth2'),
            InternalOAuthError = require('passport-oauth1').InternalOAuthError;


        /**
         * Export constructors.
         */
        exports.OAuthStrategy = OAuthStrategy;
        exports.OAuth2Strategy = OAuth2Strategy;

        /**
         * Export errors.
         */
        exports.InternalOAuthError = InternalOAuthError;

    }, {
        "passport-oauth1": 11,
        "passport-oauth2": 18
    }],
    10: [function (require, module, exports) {
        /**
         * `InternalOAuthError` error.
         *
         * InternalOAuthError wraps errors generated by node-oauth.  By wrapping these
         * objects, error messages can be formatted in a manner that aids in debugging
         * OAuth issues.
         *
         * @constructor
         * @param {String} [message]
         * @param {Object|Error} [err]
         * @api public
         */
        function InternalOAuthError(message, err) {
            Error.call(this);
            Error.captureStackTrace(this, this.constructor);
            this.name = this.constructor.name;
            this.message = message;
            this.oauthError = err;
        }

        // Inherit from `Error`.
        InternalOAuthError.prototype.__proto__ = Error.prototype;

        /**
         * Returns a string representing the error.
         *
         * @return {String}
         * @api public
         */
        InternalOAuthError.prototype.toString = function () {
            var m = this.name;
            if (this.message) {
                m += ': ' + this.message;
            }
            if (this.oauthError) {
                if (this.oauthError instanceof Error) {
                    m = this.oauthError.toString();
                } else if (this.oauthError.statusCode && this.oauthError.data) {
                    m += ' (status: ' + this.oauthError.statusCode + ' data: ' + this.oauthError.data + ')';
                }
            }
            return m;
        };


        // Expose constructor.
        module.exports = InternalOAuthError;

    }, {}],
    11: [function (require, module, exports) {
        // Load modules.
        var Strategy = require('./strategy'),
            InternalOAuthError = require('./errors/internaloautherror');


        // Expose Strategy.
        exports = module.exports = Strategy;

        // Exports.
        exports.Strategy = Strategy;
        exports.InternalOAuthError = InternalOAuthError;

    }, {
        "./errors/internaloautherror": 10,
        "./strategy": 13
    }],
    12: [function (require, module, exports) {
        function SessionStore(options) {
            if (!options.key) {
                throw new TypeError('Session-based request token store requires a session key');
            }
            this._key = options.key;
        }

        SessionStore.prototype.get = function (req, token, cb) {
            if (!req.session) {
                return cb(new Error('OAuth authentication requires session support. Did you forget to use express-session middleware?'));
            }

            // Bail if the session does not contain the request token and corresponding
            // secret.  If this happens, it is most likely caused by initiating OAuth
            // from a different host than that of the callback endpoint (for example:
            // initiating from 127.0.0.1 but handling callbacks at localhost).
            if (!req.session[this._key]) {
                return cb(new Error('Failed to find request token in session'));
            }

            var tokenSecret = req.session[this._key].oauth_token_secret;
            return cb(null, tokenSecret);
        };

        SessionStore.prototype.set = function (req, token, tokenSecret, cb) {
            if (!req.session) {
                return cb(new Error('OAuth authentication requires session support. Did you forget to use express-session middleware?'));
            }

            if (!req.session[this._key]) {
                req.session[this._key] = {};
            }
            req.session[this._key].oauth_token = token;
            req.session[this._key].oauth_token_secret = tokenSecret;
            cb();
        };

        SessionStore.prototype.destroy = function (req, token, cb) {
            delete req.session[this._key].oauth_token;
            delete req.session[this._key].oauth_token_secret;
            if (Object.keys(req.session[this._key]).length === 0) {
                delete req.session[this._key];
            }
            cb();
        };


        module.exports = SessionStore;

    }, {}],
    13: [function (require, module, exports) {
        // Load modules.
        var passport = require('passport-strategy'),
            url = require('url'),
            util = require('util'),
            utils = require('./utils'),
            OAuth = require('oauth').OAuth,
            SessionRequestTokenStore = require('./requesttoken/session'),
            InternalOAuthError = require('./errors/internaloautherror');


        /**
         * Creates an instance of `OAuthStrategy`.
         *
         * The OAuth authentication strategy authenticates requests using the OAuth
         * protocol.
         *
         * OAuth provides a facility for delegated authentication, whereby users can
         * authenticate using a third-party service such as Twitter.  Delegating in this
         * manner involves a sequence of events, including redirecting the user to the
         * third-party service for authorization.  Once authorization has been obtained,
         * the user is redirected back to the application and a token can be used to
         * obtain credentials.
         *
         * Applications must supply a `verify` callback, for which the function
         * signature is:
         *
         *     function(token, tokenSecret, profile, cb) { ... }
         *
         * The verify callback is responsible for finding or creating the user, and
         * invoking `cb` with the following arguments:
         *
         *     done(err, user, info);
         *
         * `user` should be set to `false` to indicate an authentication failure.
         * Additional `info` can optionally be passed as a third argument, typically
         * used to display informational messages.  If an exception occured, `err`
         * should be set.
         *
         * Options:
         *
         *   - `requestTokenURL`       URL used to obtain an unauthorized request token
         *   - `accessTokenURL`        URL used to exchange a user-authorized request token for an access token
         *   - `userAuthorizationURL`  URL used to obtain user authorization
         *   - `consumerKey`           identifies client to service provider
         *   - `consumerSecret`        secret used to establish ownership of the consumer key
         *   - 'signatureMethod'       signature method used to sign the request (default: 'HMAC-SHA1')
         *   - `callbackURL`           URL to which the service provider will redirect the user after obtaining authorization
         *   - `passReqToCallback`     when `true`, `req` is the first argument to the verify callback (default: `false`)
         *
         * Examples:
         *
         *     passport.use(new OAuthStrategy({
         *         requestTokenURL: 'https://www.example.com/oauth/request_token',
         *         accessTokenURL: 'https://www.example.com/oauth/access_token',
         *         userAuthorizationURL: 'https://www.example.com/oauth/authorize',
         *         consumerKey: '123-456-789',
         *         consumerSecret: 'shhh-its-a-secret'
         *         callbackURL: 'https://www.example.net/auth/example/callback'
         *       },
         *       function(token, tokenSecret, profile, cb) {
         *         User.findOrCreate(..., function (err, user) {
         *           cb(err, user);
         *         });
         *       }
         *     ));
         *
         * @constructor
         * @param {Object} options
         * @param {Function} verify
         * @api public
         */
        function OAuthStrategy(options, verify) {
            if (typeof options == 'function') {
                verify = options;
                options = undefined;
            }
            options = options || {};

            if (!verify) {
                throw new TypeError('OAuthStrategy requires a verify callback');
            }
            if (!options.requestTokenURL) {
                throw new TypeError('OAuthStrategy requires a requestTokenURL option');
            }
            if (!options.accessTokenURL) {
                throw new TypeError('OAuthStrategy requires a accessTokenURL option');
            }
            if (!options.userAuthorizationURL) {
                throw new TypeError('OAuthStrategy requires a userAuthorizationURL option');
            }
            if (!options.consumerKey) {
                throw new TypeError('OAuthStrategy requires a consumerKey option');
            }
            if (options.consumerSecret === undefined) {
                throw new TypeError('OAuthStrategy requires a consumerSecret option');
            }

            passport.Strategy.call(this);
            this.name = 'oauth';
            this._verify = verify;

            // NOTE: The _oauth property is considered "protected".  Subclasses are
            //       allowed to use it when making protected resource requests to retrieve
            //       the user profile.
            this._oauth = new OAuth(options.requestTokenURL, options.accessTokenURL,
                options.consumerKey, options.consumerSecret,
                '1.0', null, options.signatureMethod || 'HMAC-SHA1',
                null, options.customHeaders);

            this._userAuthorizationURL = options.userAuthorizationURL;
            this._callbackURL = options.callbackURL;
            this._key = options.sessionKey || 'oauth';
            this._requestTokenStore = options.requestTokenStore || new SessionRequestTokenStore({
                key: this._key
            });
            this._trustProxy = options.proxy;
            this._passReqToCallback = options.passReqToCallback;
            this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
        }

        // Inherit from `passport.Strategy`.
        util.inherits(OAuthStrategy, passport.Strategy);


        /**
         * Authenticate request by delegating to a service provider using OAuth.
         *
         * @param {Object} req
         * @api protected
         */
        OAuthStrategy.prototype.authenticate = function (req, options) {
            options = options || {};

            var self = this;
            var meta = {
                requestTokenURL: this._oauth._requestUrl,
                accessTokenURL: this._oauth._accessUrl,
                userAuthorizationURL: this._userAuthorizationURL,
                consumerKey: this._oauth._consumerKey
            }

            if (req.query && req.query.oauth_token) {
                // The request being authenticated contains an oauth_token parameter in the
                // query portion of the URL.  This indicates that the service provider has
                // redirected the user back to the application, after authenticating the
                // user and obtaining their authorization.
                //
                // The value of the oauth_token parameter is the request token.  Together
                // with knowledge of the token secret (stored in the session), the request
                // token can be exchanged for an access token and token secret.
                //
                // This access token and token secret, along with the optional ability to
                // fetch profile information from the service provider, is sufficient to
                // establish the identity of the user.
                var oauthToken = req.query.oauth_token;

                function loaded(err, oauthTokenSecret, state) {
                    if (err) {
                        return self.error(err);
                    }
                    if (!oauthTokenSecret) {
                        return self.fail(state, 403);
                    }

                    // NOTE: The oauth_verifier parameter will be supplied in the query portion
                    //       of the redirect URL, if the server supports OAuth 1.0a.
                    var oauthVerifier = req.query.oauth_verifier || null;

                    self._oauth.getOAuthAccessToken(oauthToken, oauthTokenSecret, oauthVerifier, function (err, token, tokenSecret, params) {
                        if (err) {
                            return self.error(self._createOAuthError('Failed to obtain access token', err));
                        }

                        function destroyed(err) {
                            if (err) {
                                return self.error(err);
                            }

                            self._loadUserProfile(token, tokenSecret, params, function (err, profile) {
                                if (err) {
                                    return self.error(err);
                                }

                                function verified(err, user, info) {
                                    if (err) {
                                        return self.error(err);
                                    }
                                    if (!user) {
                                        return self.fail(info);
                                    }

                                    info = info || {};
                                    if (state) {
                                        info.state = state;
                                    }
                                    self.success(user, info);
                                }

                                try {
                                    if (self._passReqToCallback) {
                                        var arity = self._verify.length;
                                        if (arity == 6) {
                                            self._verify(req, token, tokenSecret, params, profile, verified);
                                        } else { // arity == 5
                                            self._verify(req, token, tokenSecret, profile, verified);
                                        }
                                    } else {
                                        var arity = self._verify.length;
                                        if (arity == 5) {
                                            self._verify(token, tokenSecret, params, profile, verified);
                                        } else { // arity == 4
                                            self._verify(token, tokenSecret, profile, verified);
                                        }
                                    }
                                } catch (ex) {
                                    return self.error(ex);
                                }
                            });
                        }

                        // The request token has been exchanged for an access token.  Since the
                        // request token is a single-use token, that data can be removed from the
                        // store.
                        try {
                            var arity = self._requestTokenStore.destroy.length;
                            if (arity == 4) {
                                self._requestTokenStore.destroy(req, oauthToken, meta, destroyed);
                            } else { // arity == 3
                                self._requestTokenStore.destroy(req, oauthToken, destroyed);
                            }
                        } catch (ex) {
                            return self.error(ex);
                        }
                    });
                }

                try {
                    var arity = self._requestTokenStore.get.length;
                    if (arity == 4) {
                        this._requestTokenStore.get(req, oauthToken, meta, loaded);
                    } else { // arity == 3
                        this._requestTokenStore.get(req, oauthToken, loaded);
                    }
                } catch (ex) {
                    return this.error(ex);
                }
            } else {
                // In order to authenticate via OAuth, the application must obtain a request
                // token from the service provider and redirect the user to the service
                // provider to obtain their authorization.  After authorization has been
                // approved the user will be redirected back the application, at which point
                // the application can exchange the request token for an access token.
                //
                // In order to successfully exchange the request token, its corresponding
                // token secret needs to be known.  The token secret will be temporarily
                // stored in the session, so that it can be retrieved upon the user being
                // redirected back to the application.

                var params = this.requestTokenParams(options);
                var callbackURL = options.callbackURL || this._callbackURL;
                if (callbackURL) {
                    var parsed = url.parse(callbackURL);
                    if (!parsed.protocol) {
                        // The callback URL is relative, resolve a fully qualified URL from the
                        // URL of the originating request.
                        callbackURL = url.resolve(utils.originalURL(req, {
                            proxy: this._trustProxy
                        }), callbackURL);
                    }
                }
                params.oauth_callback = callbackURL;

                this._oauth.getOAuthRequestToken(params, function (err, token, tokenSecret, params) {
                    if (err) {
                        return self.error(self._createOAuthError('Failed to obtain request token', err));
                    }

                    // NOTE: params will contain an oauth_callback_confirmed property set to
                    //       true, if the server supports OAuth 1.0a.
                    //       { oauth_callback_confirmed: 'true' }

                    function stored(err) {
                        if (err) {
                            return self.error(err);
                        }

                        var parsed = url.parse(self._userAuthorizationURL, true);
                        parsed.query.oauth_token = token;
                        if (!params.oauth_callback_confirmed && callbackURL) {
                            // NOTE: If oauth_callback_confirmed=true is not present when issuing a
                            //       request token, the server does not support OAuth 1.0a.  In this
                            //       circumstance, `oauth_callback` is passed when redirecting the
                            //       user to the service provider.
                            parsed.query.oauth_callback = callbackURL;
                        }
                        utils.merge(parsed.query, self.userAuthorizationParams(options));
                        delete parsed.search;
                        var location = url.format(parsed);
                        self.redirect(location);
                    }

                    try {
                        var arity = self._requestTokenStore.set.length;
                        if (arity == 5) {
                            self._requestTokenStore.set(req, token, tokenSecret, meta, stored);
                        } else { // arity == 4
                            self._requestTokenStore.set(req, token, tokenSecret, stored);
                        }
                    } catch (ex) {
                        return self.error(ex);
                    }
                });
            }
        };

        /**
         * Retrieve user profile from service provider.
         *
         * OAuth-based authentication strategies can overrride this function in order to
         * load the user's profile from the service provider.  This assists applications
         * (and users of those applications) in the initial registration process by
         * automatically submitting required information.
         *
         * @param {String} token
         * @param {String} tokenSecret
         * @param {Object} params
         * @param {Function} done
         * @api protected
         */
        OAuthStrategy.prototype.userProfile = function (token, tokenSecret, params, done) {
            return done(null, {});
        };

        /**
         * Return extra parameters to be included in the request token request.
         *
         * Some OAuth providers require additional parameters to be included when
         * issuing a request token.  Since these parameters are not standardized by the
         * OAuth specification, OAuth-based authentication strategies can overrride this
         * function in order to populate these parameters as required by the provider.
         *
         * @param {Object} options
         * @return {Object}
         * @api protected
         */
        OAuthStrategy.prototype.requestTokenParams = function (options) {
            return {};
        };

        /**
         * Return extra parameters to be included in the user authorization request.
         *
         * Some OAuth providers allow additional, non-standard parameters to be included
         * when requesting authorization.  Since these parameters are not standardized
         * by the OAuth specification, OAuth-based authentication strategies can
         * overrride this function in order to populate these parameters as required by
         * the provider.
         *
         * @param {Object} options
         * @return {Object}
         * @api protected
         */
        OAuthStrategy.prototype.userAuthorizationParams = function (options) {
            return {};
        };

        /**
         * Parse error response from OAuth endpoint.
         *
         * OAuth-based authentication strategies can overrride this function in order to
         * parse error responses received from the request token and access token
         * endpoints, allowing the most informative message to be displayed.
         *
         * If this function is not overridden, a generic error will be thrown.
         *
         * @param {String} body
         * @param {Number} status
         * @return {Error}
         * @api protected
         */
        OAuthStrategy.prototype.parseErrorResponse = function (body, status) {
            return null;
        };

        /**
         * Load user profile, contingent upon options.
         *
         * @param {String} accessToken
         * @param {Function} done
         * @api private
         */
        OAuthStrategy.prototype._loadUserProfile = function (token, tokenSecret, params, done) {
            var self = this;

            function loadIt() {
                return self.userProfile(token, tokenSecret, params, done);
            }

            function skipIt() {
                return done(null);
            }

            if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
                // async
                this._skipUserProfile(token, tokenSecret, function (err, skip) {
                    if (err) {
                        return done(err);
                    }
                    if (!skip) {
                        return loadIt();
                    }
                    return skipIt();
                });
            } else {
                var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
                if (!skip) {
                    return loadIt();
                }
                return skipIt();
            }
        };

        /**
         * Create an OAuth error.
         *
         * @param {String} message
         * @param {Object|Error} err
         * @api private
         */
        OAuthStrategy.prototype._createOAuthError = function (message, err) {
            var e;
            if (err.statusCode && err.data) {
                try {
                    e = this.parseErrorResponse(err.data, err.statusCode);
                } catch (_) {
                }
            }
            if (!e) {
                e = new InternalOAuthError(message, err);
            }
            return e;
        };


        // Expose constructor.
        module.exports = OAuthStrategy;

    }, {
        "./errors/internaloautherror": 10,
        "./requesttoken/session": 12,
        "./utils": 14,
        "oauth": 2,
        "passport-strategy": 23,
        "url": undefined,
        "util": undefined
    }],
    14: [function (require, module, exports) {
        exports.merge = require('utils-merge');

        /**
         * Reconstructs the original URL of the request.
         *
         * This function builds a URL that corresponds the original URL requested by the
         * client, including the protocol (http or https) and host.
         *
         * If the request passed through any proxies that terminate SSL, the
         * `X-Forwarded-Proto` header is used to detect if the request was encrypted to
         * the proxy, assuming that the proxy has been flagged as trusted.
         *
         * @param {http.IncomingMessage} req
         * @param {Object} [options]
         * @return {String}
         * @api private
         */
        exports.originalURL = function (req, options) {
            options = options || {};
            var app = req.app;
            if (app && app.get && app.get('trust proxy')) {
                options.proxy = true;
            }
            var trustProxy = options.proxy;

            var proto = (req.headers['x-forwarded-proto'] || '').toLowerCase(),
                tls = req.connection.encrypted || (trustProxy && 'https' == proto.split(/\s*,\s*/)[0]),
                host = (trustProxy && req.headers['x-forwarded-host']) || req.headers.host,
                protocol = tls ? 'https' : 'http',
                path = req.url || '';
            return protocol + '://' + host + path;
        };

    }, {
        "utils-merge": 36
    }],
    15: [function (require, module, exports) {
        /**
         * `AuthorizationError` error.
         *
         * AuthorizationError represents an error in response to an authorization
         * request.  For details, refer to RFC 6749, section 4.1.2.1.
         *
         * References:
         *   - [The OAuth 2.0 Authorization Framework](http://tools.ietf.org/html/rfc6749)
         *
         * @constructor
         * @param {String} [message]
         * @param {String} [code]
         * @param {String} [uri]
         * @param {Number} [status]
         * @api public
         */
        function AuthorizationError(message, code, uri, status) {
            if (!status) {
                switch (code) {
                    case 'access_denied':
                        status = 403;
                        break;
                    case 'server_error':
                        status = 502;
                        break;
                    case 'temporarily_unavailable':
                        status = 503;
                        break;
                }
            }

            Error.call(this);
            Error.captureStackTrace(this, this.constructor);
            this.name = this.constructor.name;
            this.message = message;
            this.code = code || 'server_error';
            this.uri = uri;
            this.status = status || 500;
        }

        /**
         * Inherit from `Error`.
         */
        AuthorizationError.prototype.__proto__ = Error.prototype;


        /**
         * Expose `AuthorizationError`.
         */
        module.exports = AuthorizationError;

    }, {}],
    16: [function (require, module, exports) {
        /**
         * `InternalOAuthError` error.
         *
         * InternalOAuthError wraps errors generated by node-oauth.  By wrapping these
         * objects, error messages can be formatted in a manner that aids in debugging
         * OAuth issues.
         *
         * @constructor
         * @param {String} [message]
         * @param {Object|Error} [err]
         * @api public
         */
        function InternalOAuthError(message, err) {
            Error.call(this);
            Error.captureStackTrace(this, this.constructor);
            this.name = this.constructor.name;
            this.message = message;
            this.oauthError = err;
        }

        /**
         * Inherit from `Error`.
         */
        InternalOAuthError.prototype.__proto__ = Error.prototype;

        /**
         * Returns a string representing the error.
         *
         * @return {String}
         * @api public
         */
        InternalOAuthError.prototype.toString = function () {
            var m = this.name;
            if (this.message) {
                m += ': ' + this.message;
            }
            if (this.oauthError) {
                if (this.oauthError instanceof Error) {
                    m = this.oauthError.toString();
                } else if (this.oauthError.statusCode && this.oauthError.data) {
                    m += ' (status: ' + this.oauthError.statusCode + ' data: ' + this.oauthError.data + ')';
                }
            }
            return m;
        };


        /**
         * Expose `InternalOAuthError`.
         */
        module.exports = InternalOAuthError;

    }, {}],
    17: [function (require, module, exports) {
        /**
         * `TokenError` error.
         *
         * TokenError represents an error received from a token endpoint.  For details,
         * refer to RFC 6749, section 5.2.
         *
         * References:
         *   - [The OAuth 2.0 Authorization Framework](http://tools.ietf.org/html/rfc6749)
         *
         * @constructor
         * @param {String} [message]
         * @param {String} [code]
         * @param {String} [uri]
         * @param {Number} [status]
         * @api public
         */
        function TokenError(message, code, uri, status) {
            Error.call(this);
            Error.captureStackTrace(this, this.constructor);
            this.name = this.constructor.name;
            this.message = message;
            this.code = code || 'invalid_request';
            this.uri = uri;
            this.status = status || 500;
        }

        /**
         * Inherit from `Error`.
         */
        TokenError.prototype.__proto__ = Error.prototype;


        /**
         * Expose `TokenError`.
         */
        module.exports = TokenError;

    }, {}],
    18: [function (require, module, exports) {
        // Load modules.
        var Strategy = require('./strategy'),
            AuthorizationError = require('./errors/authorizationerror'),
            TokenError = require('./errors/tokenerror'),
            InternalOAuthError = require('./errors/internaloautherror');


        // Expose Strategy.
        exports = module.exports = Strategy;

        // Exports.
        exports.Strategy = Strategy;

        exports.AuthorizationError = AuthorizationError;
        exports.TokenError = TokenError;
        exports.InternalOAuthError = InternalOAuthError;

    }, {
        "./errors/authorizationerror": 15,
        "./errors/internaloautherror": 16,
        "./errors/tokenerror": 17,
        "./strategy": 21
    }],
    19: [function (require, module, exports) {
        function NullStore(options) {
        }

        NullStore.prototype.store = function (req, cb) {
            cb();
        }

        NullStore.prototype.verify = function (req, providedState, cb) {
            cb(null, true);
        }


        module.exports = NullStore;

    }, {}],
    20: [function (require, module, exports) {
        var uid = require('uid2');

        /**
         * Creates an instance of `SessionStore`.
         *
         * This is the state store implementation for the OAuth2Strategy used when
         * the `state` option is enabled.  It generates a random state and stores it in
         * `req.session` and verifies it when the service provider redirects the user
         * back to the application.
         *
         * This state store requires session support.  If no session exists, an error
         * will be thrown.
         *
         * Options:
         *
         *   - `key`  The key in the session under which to store the state
         *
         * @constructor
         * @param {Object} options
         * @api public
         */
        function SessionStore(options) {
            if (!options.key) {
                throw new TypeError('Session-based state store requires a session key');
            }
            this._key = options.key;
        }

        /**
         * Store request state.
         *
         * This implementation simply generates a random string and stores the value in
         * the session, where it will be used for verification when the user is
         * redirected back to the application.
         *
         * @param {Object} req
         * @param {Function} callback
         * @api protected
         */
        SessionStore.prototype.store = function (req, callback) {
            if (!req.session) {
                return callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?'));
            }

            var key = this._key;
            var state = uid(24);
            if (!req.session[key]) {
                req.session[key] = {};
            }
            req.session[key].state = state;
            callback(null, state);
        };

        /**
         * Verify request state.
         *
         * This implementation simply compares the state parameter in the request to the
         * value generated earlier and stored in the session.
         *
         * @param {Object} req
         * @param {String} providedState
         * @param {Function} callback
         * @api protected
         */
        SessionStore.prototype.verify = function (req, providedState, callback) {
            if (!req.session) {
                return callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?'));
            }

            var key = this._key;
            if (!req.session[key]) {
                return callback(null, false, {
                    message: 'Unable to verify authorization request state.'
                });
            }

            var state = req.session[key].state;
            if (!state) {
                return callback(null, false, {
                    message: 'Unable to verify authorization request state.'
                });
            }

            delete req.session[key].state;
            if (Object.keys(req.session[key]).length === 0) {
                delete req.session[key];
            }

            if (state !== providedState) {
                return callback(null, false, {
                    message: 'Invalid authorization request state.'
                });
            }

            return callback(null, true);
        };

        // Expose constructor.
        module.exports = SessionStore;

    }, {
        "uid2": 35
    }],
    21: [function (require, module, exports) {
        // Load modules.
        var passport = require('passport-strategy'),
            url = require('url'),
            util = require('util'),
            utils = require('./utils'),
            OAuth2 = require('oauth').OAuth2,
            NullStateStore = require('./state/null'),
            SessionStateStore = require('./state/session'),
            AuthorizationError = require('./errors/authorizationerror'),
            TokenError = require('./errors/tokenerror'),
            InternalOAuthError = require('./errors/internaloautherror');


        /**
         * Creates an instance of `OAuth2Strategy`.
         *
         * The OAuth 2.0 authentication strategy authenticates requests using the OAuth
         * 2.0 framework.
         *
         * OAuth 2.0 provides a facility for delegated authentication, whereby users can
         * authenticate using a third-party service such as Facebook.  Delegating in
         * this manner involves a sequence of events, including redirecting the user to
         * the third-party service for authorization.  Once authorization has been
         * granted, the user is redirected back to the application and an authorization
         * code can be used to obtain credentials.
         *
         * Applications must supply a `verify` callback, for which the function
         * signature is:
         *
         *     function(accessToken, refreshToken, profile, done) { ... }
         *
         * The verify callback is responsible for finding or creating the user, and
         * invoking `done` with the following arguments:
         *
         *     done(err, user, info);
         *
         * `user` should be set to `false` to indicate an authentication failure.
         * Additional `info` can optionally be passed as a third argument, typically
         * used to display informational messages.  If an exception occured, `err`
         * should be set.
         *
         * Options:
         *
         *   - `authorizationURL`  URL used to obtain an authorization grant
         *   - `tokenURL`          URL used to obtain an access token
         *   - `clientID`          identifies client to service provider
         *   - `clientSecret`      secret used to establish ownership of the client identifer
         *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
         *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
         *
         * Examples:
         *
         *     passport.use(new OAuth2Strategy({
         *         authorizationURL: 'https://www.example.com/oauth2/authorize',
         *         tokenURL: 'https://www.example.com/oauth2/token',
         *         clientID: '123-456-789',
         *         clientSecret: 'shhh-its-a-secret'
         *         callbackURL: 'https://www.example.net/auth/example/callback'
         *       },
         *       function(accessToken, refreshToken, profile, done) {
         *         User.findOrCreate(..., function (err, user) {
         *           done(err, user);
         *         });
         *       }
         *     ));
         *
         * @constructor
         * @param {Object} options
         * @param {Function} verify
         * @api public
         */
        function OAuth2Strategy(options, verify) {
            if (typeof options == 'function') {
                verify = options;
                options = undefined;
            }
            options = options || {};

            if (!verify) {
                throw new TypeError('OAuth2Strategy requires a verify callback');
            }
            if (!options.authorizationURL) {
                throw new TypeError('OAuth2Strategy requires a authorizationURL option');
            }
            if (!options.tokenURL) {
                throw new TypeError('OAuth2Strategy requires a tokenURL option');
            }
            if (!options.clientID) {
                throw new TypeError('OAuth2Strategy requires a clientID option');
            }

            passport.Strategy.call(this);
            this.name = 'oauth2';
            this._verify = verify;

            // NOTE: The _oauth2 property is considered "protected".  Subclasses are
            //       allowed to use it when making protected resource requests to retrieve
            //       the user profile.
            this._oauth2 = new OAuth2(options.clientID, options.clientSecret,
                '', options.authorizationURL, options.tokenURL, options.customHeaders);

            this._callbackURL = options.callbackURL;
            this._scope = options.scope;
            this._scopeSeparator = options.scopeSeparator || ' ';
            this._key = options.sessionKey || ('oauth2:' + url.parse(options.authorizationURL).hostname);

            if (options.store) {
                this._stateStore = options.store;
            } else {
                if (options.state) {
                    this._stateStore = new SessionStateStore({
                        key: this._key
                    });
                } else {
                    this._stateStore = new NullStateStore();
                }
            }
            this._trustProxy = options.proxy;
            this._passReqToCallback = options.passReqToCallback;
            this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
        }

        // Inherit from `passport.Strategy`.
        util.inherits(OAuth2Strategy, passport.Strategy);


        /**
         * Authenticate request by delegating to a service provider using OAuth 2.0.
         *
         * @param {Object} req
         * @api protected
         */
        OAuth2Strategy.prototype.authenticate = function (req, options) {
            options = options || {};
            var self = this;

            if (req.query && req.query.error) {
                if (req.query.error == 'access_denied') {
                    return this.fail({
                        message: req.query.error_description
                    });
                } else {
                    return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
                }
            }

            var callbackURL = options.callbackURL || this._callbackURL;
            if (callbackURL) {
                var parsed = url.parse(callbackURL);
                if (!parsed.protocol) {
                    // The callback URL is relative, resolve a fully qualified URL from the
                    // URL of the originating request.
                    callbackURL = url.resolve(utils.originalURL(req, {
                        proxy: this._trustProxy
                    }), callbackURL);
                }
            }

            var meta = {
                authorizationURL: this._oauth2._authorizeUrl,
                tokenURL: this._oauth2._accessTokenUrl,
                clientID: this._oauth2._clientId
            }

            if (req.query && req.query.code) {
                function loaded(err, ok, state) {
                    if (err) {
                        return self.error(err);
                    }
                    if (!ok) {
                        return self.fail(state, 403);
                    }

                    var code = req.query.code;

                    var params = self.tokenParams(options);
                    params.grant_type = 'authorization_code';
                    if (callbackURL) {
                        params.redirect_uri = callbackURL;
                    }

                    self._oauth2.getOAuthAccessToken(code, params,
                        function (err, accessToken, refreshToken, params) {
                            if (err) {
                                return self.error(self._createOAuthError('Failed to obtain access token', err));
                            }

                            self._loadUserProfile(accessToken, function (err, profile) {
                                if (err) {
                                    return self.error(err);
                                }

                                function verified(err, user, info) {
                                    if (err) {
                                        return self.error(err);
                                    }
                                    if (!user) {
                                        return self.fail(info);
                                    }

                                    info = info || {};
                                    if (state) {
                                        info.state = state;
                                    }
                                    self.success(user, info);
                                }

                                try {
                                    if (self._passReqToCallback) {
                                        var arity = self._verify.length;
                                        if (arity == 6) {
                                            self._verify(req, accessToken, refreshToken, params, profile, verified);
                                        } else { // arity == 5
                                            self._verify(req, accessToken, refreshToken, profile, verified);
                                        }
                                    } else {
                                        var arity = self._verify.length;
                                        if (arity == 5) {
                                            self._verify(accessToken, refreshToken, params, profile, verified);
                                        } else { // arity == 4
                                            self._verify(accessToken, refreshToken, profile, verified);
                                        }
                                    }
                                } catch (ex) {
                                    return self.error(ex);
                                }
                            });
                        }
                    );
                }

                var state = req.query.state;
                try {
                    var arity = this._stateStore.verify.length;
                    if (arity == 4) {
                        this._stateStore.verify(req, state, meta, loaded);
                    } else { // arity == 3
                        this._stateStore.verify(req, state, loaded);
                    }
                } catch (ex) {
                    return this.error(ex);
                }
            } else {
                var params = this.authorizationParams(options);
                params.response_type = 'code';
                if (callbackURL) {
                    params.redirect_uri = callbackURL;
                }
                var scope = options.scope || this._scope;
                if (scope) {
                    if (Array.isArray(scope)) {
                        scope = scope.join(this._scopeSeparator);
                    }
                    params.scope = scope;
                }

                var state = options.state;
                if (state) {
                    params.state = state;

                    var parsed = url.parse(this._oauth2._authorizeUrl, true);
                    utils.merge(parsed.query, params);
                    parsed.query['client_id'] = this._oauth2._clientId;
                    delete parsed.search;
                    var location = url.format(parsed);
                    this.redirect(location);
                } else {
                    function stored(err, state) {
                        if (err) {
                            return self.error(err);
                        }

                        if (state) {
                            params.state = state;
                        }
                        var parsed = url.parse(self._oauth2._authorizeUrl, true);
                        utils.merge(parsed.query, params);
                        parsed.query['client_id'] = self._oauth2._clientId;
                        delete parsed.search;
                        var location = url.format(parsed);
                        self.redirect(location);
                    }

                    try {
                        var arity = this._stateStore.store.length;
                        if (arity == 3) {
                            this._stateStore.store(req, meta, stored);
                        } else { // arity == 2
                            this._stateStore.store(req, stored);
                        }
                    } catch (ex) {
                        return this.error(ex);
                    }
                }
            }
        };

        /**
         * Retrieve user profile from service provider.
         *
         * OAuth 2.0-based authentication strategies can overrride this function in
         * order to load the user's profile from the service provider.  This assists
         * applications (and users of those applications) in the initial registration
         * process by automatically submitting required information.
         *
         * @param {String} accessToken
         * @param {Function} done
         * @api protected
         */
        OAuth2Strategy.prototype.userProfile = function (accessToken, done) {
            return done(null, {});
        };

        /**
         * Return extra parameters to be included in the authorization request.
         *
         * Some OAuth 2.0 providers allow additional, non-standard parameters to be
         * included when requesting authorization.  Since these parameters are not
         * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
         * strategies can overrride this function in order to populate these parameters
         * as required by the provider.
         *
         * @param {Object} options
         * @return {Object}
         * @api protected
         */
        OAuth2Strategy.prototype.authorizationParams = function (options) {
            return {};
        };

        /**
         * Return extra parameters to be included in the token request.
         *
         * Some OAuth 2.0 providers allow additional, non-standard parameters to be
         * included when requesting an access token.  Since these parameters are not
         * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
         * strategies can overrride this function in order to populate these parameters
         * as required by the provider.
         *
         * @return {Object}
         * @api protected
         */
        OAuth2Strategy.prototype.tokenParams = function (options) {
            return {};
        };

        /**
         * Parse error response from OAuth 2.0 endpoint.
         *
         * OAuth 2.0-based authentication strategies can overrride this function in
         * order to parse error responses received from the token endpoint, allowing the
         * most informative message to be displayed.
         *
         * If this function is not overridden, the body will be parsed in accordance
         * with RFC 6749, section 5.2.
         *
         * @param {String} body
         * @param {Number} status
         * @return {Error}
         * @api protected
         */
        OAuth2Strategy.prototype.parseErrorResponse = function (body, status) {
            var json = JSON.parse(body);
            if (json.error) {
                return new TokenError(json.error_description, json.error, json.error_uri);
            }
            return null;
        };

        /**
         * Load user profile, contingent upon options.
         *
         * @param {String} accessToken
         * @param {Function} done
         * @api private
         */
        OAuth2Strategy.prototype._loadUserProfile = function (accessToken, done) {
            var self = this;

            function loadIt() {
                return self.userProfile(accessToken, done);
            }

            function skipIt() {
                return done(null);
            }

            if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
                // async
                this._skipUserProfile(accessToken, function (err, skip) {
                    if (err) {
                        return done(err);
                    }
                    if (!skip) {
                        return loadIt();
                    }
                    return skipIt();
                });
            } else {
                var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
                if (!skip) {
                    return loadIt();
                }
                return skipIt();
            }
        };

        /**
         * Create an OAuth error.
         *
         * @param {String} message
         * @param {Object|Error} err
         * @api private
         */
        OAuth2Strategy.prototype._createOAuthError = function (message, err) {
            var e;
            if (err.statusCode && err.data) {
                try {
                    e = this.parseErrorResponse(err.data, err.statusCode);
                } catch (_) {
                }
            }
            if (!e) {
                e = new InternalOAuthError(message, err);
            }
            return e;
        };


        // Expose constructor.
        module.exports = OAuth2Strategy;

    }, {
        "./errors/authorizationerror": 15,
        "./errors/internaloautherror": 16,
        "./errors/tokenerror": 17,
        "./state/null": 19,
        "./state/session": 20,
        "./utils": 22,
        "oauth": 2,
        "passport-strategy": 23,
        "url": undefined,
        "util": undefined
    }],
    22: [function (require, module, exports) {
        arguments[4][14][0].apply(exports, arguments)
    }, {
        "dup": 14,
        "utils-merge": 36
    }],
    23: [function (require, module, exports) {
        /**
         * Module dependencies.
         */
        var Strategy = require('./strategy');


        /**
         * Expose `Strategy` directly from package.
         */
        exports = module.exports = Strategy;

        /**
         * Export constructors.
         */
        exports.Strategy = Strategy;

    }, {
        "./strategy": 24
    }],
    24: [function (require, module, exports) {
        /**
         * Creates an instance of `Strategy`.
         *
         * @constructor
         * @api public
         */
        function Strategy() {
        }

        /**
         * Authenticate request.
         *
         * This function must be overridden by subclasses.  In abstract form, it always
         * throws an exception.
         *
         * @param {Object} req The request to authenticate.
         * @param {Object} [options] Strategy-specific options.
         * @api public
         */
        Strategy.prototype.authenticate = function (req, options) {
            throw new Error('Strategy#authenticate must be overridden by subclass');
        };


        /**
         * Expose `Strategy`.
         */
        module.exports = Strategy;

    }, {}],
    25: [function (require, module, exports) {
        /**
         * Module dependencies.
         */
        var SessionStrategy = require('./strategies/session');


        /**
         * `Authenticator` constructor.
         *
         * @api public
         */
        function Authenticator() {
            this._key = 'passport';
            this._strategies = {};
            this._serializers = [];
            this._deserializers = [];
            this._infoTransformers = [];
            this._framework = null;
            this._userProperty = 'user';

            this.init();
        }

        /**
         * Initialize authenticator.
         *
         * @api protected
         */
        Authenticator.prototype.init = function () {
            this.framework(require('./framework/connect')());
            this.use(new SessionStrategy());
        };

        /**
         * Utilize the given `strategy` with optional `name`, overridding the strategy's
         * default name.
         *
         * Examples:
         *
         *     passport.use(new TwitterStrategy(...));
         *
         *     passport.use('api', new http.BasicStrategy(...));
         *
         * @param {String|Strategy} name
         * @param {Strategy} strategy
         * @return {Authenticator} for chaining
         * @api public
         */
        Authenticator.prototype.use = function (name, strategy) {
            if (!strategy) {
                strategy = name;
                name = strategy.name;
            }
            if (!name) {
                throw new Error('Authentication strategies must have a name');
            }

            this._strategies[name] = strategy;
            return this;
        };

        /**
         * Un-utilize the `strategy` with given `name`.
         *
         * In typical applications, the necessary authentication strategies are static,
         * configured once and always available.  As such, there is often no need to
         * invoke this function.
         *
         * However, in certain situations, applications may need dynamically configure
         * and de-configure authentication strategies.  The `use()`/`unuse()`
         * combination satisfies these scenarios.
         *
         * Examples:
         *
         *     passport.unuse('legacy-api');
         *
         * @param {String} name
         * @return {Authenticator} for chaining
         * @api public
         */
        Authenticator.prototype.unuse = function (name) {
            delete this._strategies[name];
            return this;
        };

        /**
         * Setup Passport to be used under framework.
         *
         * By default, Passport exposes middleware that operate using Connect-style
         * middleware using a `fn(req, res, next)` signature.  Other popular frameworks
         * have different expectations, and this function allows Passport to be adapted
         * to operate within such environments.
         *
         * If you are using a Connect-compatible framework, including Express, there is
         * no need to invoke this function.
         *
         * Examples:
         *
         *     passport.framework(require('hapi-passport')());
         *
         * @param {Object} name
         * @return {Authenticator} for chaining
         * @api public
         */
        Authenticator.prototype.framework = function (fw) {
            this._framework = fw;
            return this;
        };

        /**
         * Passport's primary initialization middleware.
         *
         * This middleware must be in use by the Connect/Express application for
         * Passport to operate.
         *
         * Options:
         *   - `userProperty`  Property to set on `req` upon login, defaults to _user_
         *
         * Examples:
         *
         *     app.use(passport.initialize());
         *
         *     app.use(passport.initialize({ userProperty: 'currentUser' }));
         *
         * @param {Object} options
         * @return {Function} middleware
         * @api public
         */
        Authenticator.prototype.initialize = function (options) {
            options = options || {};
            this._userProperty = options.userProperty || 'user';

            return this._framework.initialize(this, options);
        };

        /**
         * Middleware that will authenticate a request using the given `strategy` name,
         * with optional `options` and `callback`.
         *
         * Examples:
         *
         *     passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' })(req, res);
         *
         *     passport.authenticate('local', function(err, user) {
         *       if (!user) { return res.redirect('/login'); }
         *       res.end('Authenticated!');
         *     })(req, res);
         *
         *     passport.authenticate('basic', { session: false })(req, res);
         *
         *     app.get('/auth/twitter', passport.authenticate('twitter'), function(req, res) {
         *       // request will be redirected to Twitter
         *     });
         *     app.get('/auth/twitter/callback', passport.authenticate('twitter'), function(req, res) {
         *       res.json(req.user);
         *     });
         *
         * @param {String} strategy
         * @param {Object} options
         * @param {Function} callback
         * @return {Function} middleware
         * @api public
         */
        Authenticator.prototype.authenticate = function (strategy, options, callback) {
            return this._framework.authenticate(this, strategy, options, callback);
        };

        /**
         * Middleware that will authorize a third-party account using the given
         * `strategy` name, with optional `options`.
         *
         * If authorization is successful, the result provided by the strategy's verify
         * callback will be assigned to `req.account`.  The existing login session and
         * `req.user` will be unaffected.
         *
         * This function is particularly useful when connecting third-party accounts
         * to the local account of a user that is currently authenticated.
         *
         * Examples:
         *
         *    passport.authorize('twitter-authz', { failureRedirect: '/account' });
         *
         * @param {String} strategy
         * @param {Object} options
         * @return {Function} middleware
         * @api public
         */
        Authenticator.prototype.authorize = function (strategy, options, callback) {
            options = options || {};
            options.assignProperty = 'account';

            var fn = this._framework.authorize || this._framework.authenticate;
            return fn(this, strategy, options, callback);
        };

        /**
         * Middleware that will restore login state from a session.
         *
         * Web applications typically use sessions to maintain login state between
         * requests.  For example, a user will authenticate by entering credentials into
         * a form which is submitted to the server.  If the credentials are valid, a
         * login session is established by setting a cookie containing a session
         * identifier in the user's web browser.  The web browser will send this cookie
         * in subsequent requests to the server, allowing a session to be maintained.
         *
         * If sessions are being utilized, and a login session has been established,
         * this middleware will populate `req.user` with the current user.
         *
         * Note that sessions are not strictly required for Passport to operate.
         * However, as a general rule, most web applications will make use of sessions.
         * An exception to this rule would be an API server, which expects each HTTP
         * request to provide credentials in an Authorization header.
         *
         * Examples:
         *
         *     app.use(connect.cookieParser());
         *     app.use(connect.session({ secret: 'keyboard cat' }));
         *     app.use(passport.initialize());
         *     app.use(passport.session());
         *
         * Options:
         *   - `pauseStream`      Pause the request stream before deserializing the user
         *                        object from the session.  Defaults to _false_.  Should
         *                        be set to true in cases where middleware consuming the
         *                        request body is configured after passport and the
         *                        deserializeUser method is asynchronous.
         *
         * @param {Object} options
         * @return {Function} middleware
         * @api public
         */
        Authenticator.prototype.session = function (options) {
            return this.authenticate('session', options);
        };

        /**
         * Registers a function used to serialize user objects into the session.
         *
         * Examples:
         *
         *     passport.serializeUser(function(user, done) {
         *       done(null, user.id);
         *     });
         *
         * @api public
         */
        Authenticator.prototype.serializeUser = function (fn, req, done) {
            if (typeof fn === 'function') {
                return this._serializers.push(fn);
            }

            // private implementation that traverses the chain of serializers, attempting
            // to serialize a user
            var user = fn;

            // For backwards compatibility
            if (typeof req === 'function') {
                done = req;
                req = undefined;
            }

            var stack = this._serializers;
            (function pass(i, err, obj) {
                // serializers use 'pass' as an error to skip processing
                if ('pass' === err) {
                    err = undefined;
                }
                // an error or serialized object was obtained, done
                if (err || obj || obj === 0) {
                    return done(err, obj);
                }

                var layer = stack[i];
                if (!layer) {
                    return done(new Error('Failed to serialize user into session'));
                }


                function serialized(e, o) {
                    pass(i + 1, e, o);
                }

                try {
                    var arity = layer.length;
                    if (arity == 3) {
                        layer(req, user, serialized);
                    } else {
                        layer(user, serialized);
                    }
                } catch (e) {
                    return done(e);
                }
            })(0);
        };

        /**
         * Registers a function used to deserialize user objects out of the session.
         *
         * Examples:
         *
         *     passport.deserializeUser(function(id, done) {
         *       User.findById(id, function (err, user) {
         *         done(err, user);
         *       });
         *     });
         *
         * @api public
         */
        Authenticator.prototype.deserializeUser = function (fn, req, done) {
            if (typeof fn === 'function') {
                return this._deserializers.push(fn);
            }

            // private implementation that traverses the chain of deserializers,
            // attempting to deserialize a user
            var obj = fn;

            // For backwards compatibility
            if (typeof req === 'function') {
                done = req;
                req = undefined;
            }

            var stack = this._deserializers;
            (function pass(i, err, user) {
                // deserializers use 'pass' as an error to skip processing
                if ('pass' === err) {
                    err = undefined;
                }
                // an error or deserialized user was obtained, done
                if (err || user) {
                    return done(err, user);
                }
                // a valid user existed when establishing the session, but that user has
                // since been removed
                if (user === null || user === false) {
                    return done(null, false);
                }

                var layer = stack[i];
                if (!layer) {
                    return done(new Error('Failed to deserialize user out of session'));
                }


                function deserialized(e, u) {
                    pass(i + 1, e, u);
                }

                try {
                    var arity = layer.length;
                    if (arity == 3) {
                        layer(req, obj, deserialized);
                    } else {
                        layer(obj, deserialized);
                    }
                } catch (e) {
                    return done(e);
                }
            })(0);
        };

        /**
         * Registers a function used to transform auth info.
         *
         * In some circumstances authorization details are contained in authentication
         * credentials or loaded as part of verification.
         *
         * For example, when using bearer tokens for API authentication, the tokens may
         * encode (either directly or indirectly in a database), details such as scope
         * of access or the client to which the token was issued.
         *
         * Such authorization details should be enforced separately from authentication.
         * Because Passport deals only with the latter, this is the responsiblity of
         * middleware or routes further along the chain.  However, it is not optimal to
         * decode the same data or execute the same database query later.  To avoid
         * this, Passport accepts optional `info` along with the authenticated `user`
         * in a strategy's `success()` action.  This info is set at `req.authInfo`,
         * where said later middlware or routes can access it.
         *
         * Optionally, applications can register transforms to proccess this info,
         * which take effect prior to `req.authInfo` being set.  This is useful, for
         * example, when the info contains a client ID.  The transform can load the
         * client from the database and include the instance in the transformed info,
         * allowing the full set of client properties to be convieniently accessed.
         *
         * If no transforms are registered, `info` supplied by the strategy will be left
         * unmodified.
         *
         * Examples:
         *
         *     passport.transformAuthInfo(function(info, done) {
         *       Client.findById(info.clientID, function (err, client) {
         *         info.client = client;
         *         done(err, info);
         *       });
         *     });
         *
         * @api public
         */
        Authenticator.prototype.transformAuthInfo = function (fn, req, done) {
            if (typeof fn === 'function') {
                return this._infoTransformers.push(fn);
            }

            // private implementation that traverses the chain of transformers,
            // attempting to transform auth info
            var info = fn;

            // For backwards compatibility
            if (typeof req === 'function') {
                done = req;
                req = undefined;
            }

            var stack = this._infoTransformers;
            (function pass(i, err, tinfo) {
                // transformers use 'pass' as an error to skip processing
                if ('pass' === err) {
                    err = undefined;
                }
                // an error or transformed info was obtained, done
                if (err || tinfo) {
                    return done(err, tinfo);
                }

                var layer = stack[i];
                if (!layer) {
                    // if no transformers are registered (or they all pass), the default
                    // behavior is to use the un-transformed info as-is
                    return done(null, info);
                }


                function transformed(e, t) {
                    pass(i + 1, e, t);
                }

                try {
                    var arity = layer.length;
                    if (arity == 1) {
                        // sync
                        var t = layer(info);
                        transformed(null, t);
                    } else if (arity == 3) {
                        layer(req, info, transformed);
                    } else {
                        layer(info, transformed);
                    }
                } catch (e) {
                    return done(e);
                }
            })(0);
        };

        /**
         * Return strategy with given `name`.
         *
         * @param {String} name
         * @return {Strategy}
         * @api private
         */
        Authenticator.prototype._strategy = function (name) {
            return this._strategies[name];
        };


        /**
         * Expose `Authenticator`.
         */
        module.exports = Authenticator;

    }, {
        "./framework/connect": 27,
        "./strategies/session": 32
    }],
    26: [function (require, module, exports) {
        /**
         * `AuthenticationError` error.
         *
         * @api private
         */
        function AuthenticationError(message, status) {
            Error.call(this);
            Error.captureStackTrace(this, arguments.callee);
            this.name = 'AuthenticationError';
            this.message = message;
            this.status = status || 401;
        }

        /**
         * Inherit from `Error`.
         */
        AuthenticationError.prototype.__proto__ = Error.prototype;


        /**
         * Expose `AuthenticationError`.
         */
        module.exports = AuthenticationError;

    }, {}],
    27: [function (require, module, exports) {
        /**
         * Module dependencies.
         */
        var initialize = require('../middleware/initialize'),
            authenticate = require('../middleware/authenticate');

        /**
         * Framework support for Connect/Express.
         *
         * This module provides support for using Passport with Express.  It exposes
         * middleware that conform to the `fn(req, res, next)` signature and extends
         * Node's built-in HTTP request object with useful authentication-related
         * functions.
         *
         * @return {Object}
         * @api protected
         */
        exports = module.exports = function () {

            // HTTP extensions.
            exports.__monkeypatchNode();

            return {
                initialize: initialize,
                authenticate: authenticate
            };
        };

        exports.__monkeypatchNode = function () {
            var http = require('http');
            var IncomingMessageExt = require('../http/request');

            http.IncomingMessage.prototype.login =
                http.IncomingMessage.prototype.logIn = IncomingMessageExt.logIn;
            http.IncomingMessage.prototype.logout =
                http.IncomingMessage.prototype.logOut = IncomingMessageExt.logOut;
            http.IncomingMessage.prototype.isAuthenticated = IncomingMessageExt.isAuthenticated;
            http.IncomingMessage.prototype.isUnauthenticated = IncomingMessageExt.isUnauthenticated;
        };

    }, {
        "../http/request": 28,
        "../middleware/authenticate": 30,
        "../middleware/initialize": 31,
        "http": undefined
    }],
    28: [function (require, module, exports) {
        /**
         * Module dependencies.
         */
            //var http = require('http')
            //  , req = http.IncomingMessage.prototype;


        var req = exports = module.exports = {};

        /**
         * Intiate a login session for `user`.
         *
         * Options:
         *   - `session`  Save login state in session, defaults to _true_
         *
         * Examples:
         *
         *     req.logIn(user, { session: false });
         *
         *     req.logIn(user, function(err) {
         *       if (err) { throw err; }
         *       // session saved
         *     });
         *
         * @param {User} user
         * @param {Object} options
         * @param {Function} done
         * @api public
         */
        req.login =
            req.logIn = function (user, options, done) {
                if (typeof options == 'function') {
                    done = options;
                    options = {};
                }
                options = options || {};

                var property = 'user';
                if (this._passport && this._passport.instance) {
                    property = this._passport.instance._userProperty || 'user';
                }
                var session = (options.session === undefined) ? true : options.session;

                this[property] = user;
                if (session) {
                    if (!this._passport) {
                        throw new Error('passport.initialize() middleware not in use');
                    }
                    if (typeof done != 'function') {
                        throw new Error('req#login requires a callback function');
                    }

                    var self = this;
                    this._passport.instance.serializeUser(user, this, function (err, obj) {
                        if (err) {
                            self[property] = null;
                            return done(err);
                        }
                        if (!self._passport.session) {
                            self._passport.session = {};
                        }
                        self._passport.session.user = obj;
                        if (!self.session) {
                            self.session = {};
                        }
                        self.session[self._passport.instance._key] = self._passport.session;
                        done();
                    });
                } else {
                    done && done();
                }
            };

        /**
         * Terminate an existing login session.
         *
         * @api public
         */
        req.logout =
            req.logOut = function () {
                var property = 'user';
                if (this._passport && this._passport.instance) {
                    property = this._passport.instance._userProperty || 'user';
                }

                this[property] = null;
                if (this._passport && this._passport.session) {
                    delete this._passport.session.user;
                }
            };

        /**
         * Test if request is authenticated.
         *
         * @return {Boolean}
         * @api public
         */
        req.isAuthenticated = function () {
            var property = 'user';
            if (this._passport && this._passport.instance) {
                property = this._passport.instance._userProperty || 'user';
            }

            return (this[property]) ? true : false;
        };

        /**
         * Test if request is unauthenticated.
         *
         * @return {Boolean}
         * @api public
         */
        req.isUnauthenticated = function () {
            return !this.isAuthenticated();
        };

    }, {}],
    29: [function (require, module, exports) {
        /**
         * Module dependencies.
         */
        var Passport = require('./authenticator'),
            SessionStrategy = require('./strategies/session');


        /**
         * Export default singleton.
         *
         * @api public
         */
        exports = module.exports = new Passport();

        /**
         * Expose constructors.
         */
        exports.Passport =
            exports.Authenticator = Passport;
        exports.Strategy = require('passport-strategy');

        /**
         * Expose strategies.
         */
        exports.strategies = {};
        exports.strategies.SessionStrategy = SessionStrategy;

    }, {
        "./authenticator": 25,
        "./strategies/session": 32,
        "passport-strategy": 23
    }],
    30: [function (require, module, exports) {
        /**
         * Module dependencies.
         */
        var http = require('http'),
            IncomingMessageExt = require('../http/request'),
            AuthenticationError = require('../errors/authenticationerror');


        /**
         * Authenticates requests.
         *
         * Applies the `name`ed strategy (or strategies) to the incoming request, in
         * order to authenticate the request.  If authentication is successful, the user
         * will be logged in and populated at `req.user` and a session will be
         * established by default.  If authentication fails, an unauthorized response
         * will be sent.
         *
         * Options:
         *   - `session`          Save login state in session, defaults to _true_
         *   - `successRedirect`  After successful login, redirect to given URL
         *   - `failureRedirect`  After failed login, redirect to given URL
         *   - `assignProperty`   Assign the object provided by the verify callback to given property
         *
         * An optional `callback` can be supplied to allow the application to overrride
         * the default manner in which authentication attempts are handled.  The
         * callback has the following signature, where `user` will be set to the
         * authenticated user on a successful authentication attempt, or `false`
         * otherwise.  An optional `info` argument will be passed, containing additional
         * details provided by the strategy's verify callback.
         *
         *     app.get('/protected', function(req, res, next) {
         *       passport.authenticate('local', function(err, user, info) {
         *         if (err) { return next(err) }
         *         if (!user) { return res.redirect('/signin') }
         *         res.redirect('/account');
         *       })(req, res, next);
         *     });
         *
         * Note that if a callback is supplied, it becomes the application's
         * responsibility to log-in the user, establish a session, and otherwise perform
         * the desired operations.
         *
         * Examples:
         *
         *     passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' });
         *
         *     passport.authenticate('basic', { session: false });
         *
         *     passport.authenticate('twitter');
         *
         * @param {String|Array} name
         * @param {Object} options
         * @param {Function} callback
         * @return {Function}
         * @api public
         */
        module.exports = function authenticate(passport, name, options, callback) {
            if (typeof options == 'function') {
                callback = options;
                options = {};
            }
            options = options || {};

            var multi = true;

            // Cast `name` to an array, allowing authentication to pass through a chain of
            // strategies.  The first strategy to succeed, redirect, or error will halt
            // the chain.  Authentication failures will proceed through each strategy in
            // series, ultimately failing if all strategies fail.
            //
            // This is typically used on API endpoints to allow clients to authenticate
            // using their preferred choice of Basic, Digest, token-based schemes, etc.
            // It is not feasible to construct a chain of multiple strategies that involve
            // redirection (for example both Facebook and Twitter), since the first one to
            // redirect will halt the chain.
            if (!Array.isArray(name)) {
                name = [name];
                multi = false;
            }

            return function authenticate(req, res, next) {
                if (http.IncomingMessage.prototype.logIn &&
                    http.IncomingMessage.prototype.logIn !== IncomingMessageExt.logIn) {
                    require('../framework/connect').__monkeypatchNode();
                }


                // accumulator for failures from each strategy in the chain
                var failures = [];

                function allFailed() {
                    if (callback) {
                        if (!multi) {
                            return callback(null, false, failures[0].challenge, failures[0].status);
                        } else {
                            var challenges = failures.map(function (f) {
                                return f.challenge;
                            });
                            var statuses = failures.map(function (f) {
                                return f.status;
                            });
                            return callback(null, false, challenges, statuses);
                        }
                    }

                    // Strategies are ordered by priority.  For the purpose of flashing a
                    // message, the first failure will be displayed.
                    var failure = failures[0] || {},
                        challenge = failure.challenge || {},
                        msg;

                    if (options.failureFlash) {
                        var flash = options.failureFlash;
                        if (typeof flash == 'string') {
                            flash = {
                                type: 'error',
                                message: flash
                            };
                        }
                        flash.type = flash.type || 'error';

                        var type = flash.type || challenge.type || 'error';
                        msg = flash.message || challenge.message || challenge;
                        if (typeof msg == 'string') {
                            req.flash(type, msg);
                        }
                    }
                    if (options.failureMessage) {
                        msg = options.failureMessage;
                        if (typeof msg == 'boolean') {
                            msg = challenge.message || challenge;
                        }
                        if (typeof msg == 'string') {
                            req.session.messages = req.session.messages || [];
                            req.session.messages.push(msg);
                        }
                    }
                    if (options.failureRedirect) {
                        return res.redirect(options.failureRedirect);
                    }

                    // When failure handling is not delegated to the application, the default
                    // is to respond with 401 Unauthorized.  Note that the WWW-Authenticate
                    // header will be set according to the strategies in use (see
                    // actions#fail).  If multiple strategies failed, each of their challenges
                    // will be included in the response.
                    var rchallenge = [],
                        rstatus, status;

                    for (var j = 0, len = failures.length; j < len; j++) {
                        failure = failures[j];
                        challenge = failure.challenge;
                        status = failure.status;

                        rstatus = rstatus || status;
                        if (typeof challenge == 'string') {
                            rchallenge.push(challenge);
                        }
                    }

                    res.statusCode = rstatus || 401;
                    if (res.statusCode == 401 && rchallenge.length) {
                        res.setHeader('WWW-Authenticate', rchallenge);
                    }
                    if (options.failWithError) {
                        return next(new AuthenticationError(http.STATUS_CODES[res.statusCode], rstatus));
                    }
                    res.end(http.STATUS_CODES[res.statusCode]);
                }

                (function attempt(i) {
                    var layer = name[i];
                    // If no more strategies exist in the chain, authentication has failed.
                    if (!layer) {
                        return allFailed();
                    }

                    // Get the strategy, which will be used as prototype from which to create
                    // a new instance.  Action functions will then be bound to the strategy
                    // within the context of the HTTP request/response pair.
                    var prototype = passport._strategy(layer);
                    if (!prototype) {
                        return next(new Error('Unknown authentication strategy "' + layer + '"'));
                    }

                    var strategy = Object.create(prototype);


                    // ----- BEGIN STRATEGY AUGMENTATION -----
                    // Augment the new strategy instance with action functions.  These action
                    // functions are bound via closure the the request/response pair.  The end
                    // goal of the strategy is to invoke *one* of these action methods, in
                    // order to indicate successful or failed authentication, redirect to a
                    // third-party identity provider, etc.

                    /**
                     * Authenticate `user`, with optional `info`.
                     *
                     * Strategies should call this function to successfully authenticate a
                     * user.  `user` should be an object supplied by the application after it
                     * has been given an opportunity to verify credentials.  `info` is an
                     * optional argument containing additional user information.  This is
                     * useful for third-party authentication strategies to pass profile
                     * details.
                     *
                     * @param {Object} user
                     * @param {Object} info
                     * @api public
                     */
                    strategy.success = function (user, info) {
                        if (callback) {
                            return callback(null, user, info);
                        }

                        info = info || {};
                        var msg;

                        if (options.successFlash) {
                            var flash = options.successFlash;
                            if (typeof flash == 'string') {
                                flash = {
                                    type: 'success',
                                    message: flash
                                };
                            }
                            flash.type = flash.type || 'success';

                            var type = flash.type || info.type || 'success';
                            msg = flash.message || info.message || info;
                            if (typeof msg == 'string') {
                                req.flash(type, msg);
                            }
                        }
                        if (options.successMessage) {
                            msg = options.successMessage;
                            if (typeof msg == 'boolean') {
                                msg = info.message || info;
                            }
                            if (typeof msg == 'string') {
                                req.session.messages = req.session.messages || [];
                                req.session.messages.push(msg);
                            }
                        }
                        if (options.assignProperty) {
                            req[options.assignProperty] = user;
                            return next();
                        }

                        req.logIn(user, options, function (err) {
                            if (err) {
                                return next(err);
                            }

                            function complete() {
                                if (options.successReturnToOrRedirect) {
                                    var url = options.successReturnToOrRedirect;
                                    if (req.session && req.session.returnTo) {
                                        url = req.session.returnTo;
                                        delete req.session.returnTo;
                                    }
                                    return res.redirect(url);
                                }
                                if (options.successRedirect) {
                                    return res.redirect(options.successRedirect);
                                }
                                next();
                            }

                            if (options.authInfo !== false) {
                                passport.transformAuthInfo(info, req, function (err, tinfo) {
                                    if (err) {
                                        return next(err);
                                    }
                                    req.authInfo = tinfo;
                                    complete();
                                });
                            } else {
                                complete();
                            }
                        });
                    };

                    /**
                     * Fail authentication, with optional `challenge` and `status`, defaulting
                     * to 401.
                     *
                     * Strategies should call this function to fail an authentication attempt.
                     *
                     * @param {String} challenge
                     * @param {Number} status
                     * @api public
                     */
                    strategy.fail = function (challenge, status) {
                        if (typeof challenge == 'number') {
                            status = challenge;
                            challenge = undefined;
                        }

                        // push this failure into the accumulator and attempt authentication
                        // using the next strategy
                        failures.push({
                            challenge: challenge,
                            status: status
                        });
                        attempt(i + 1);
                    };

                    /**
                     * Redirect to `url` with optional `status`, defaulting to 302.
                     *
                     * Strategies should call this function to redirect the user (via their
                     * user agent) to a third-party website for authentication.
                     *
                     * @param {String} url
                     * @param {Number} status
                     * @api public
                     */
                    strategy.redirect = function (url, status) {
                        // NOTE: Do not use `res.redirect` from Express, because it can't decide
                        //       what it wants.
                        //
                        //       Express 2.x: res.redirect(url, status)
                        //       Express 3.x: res.redirect(status, url) -OR- res.redirect(url, status)
                        //         - as of 3.14.0, deprecated warnings are issued if res.redirect(url, status)
                        //           is used
                        //       Express 4.x: res.redirect(status, url)
                        //         - all versions (as of 4.8.7) continue to accept res.redirect(url, status)
                        //           but issue deprecated versions

                        res.statusCode = status || 302;
                        res.setHeader('Location', url);
                        res.setHeader('Content-Length', '0');
                        res.end();
                    };

                    /**
                     * Pass without making a success or fail decision.
                     *
                     * Under most circumstances, Strategies should not need to call this
                     * function.  It exists primarily to allow previous authentication state
                     * to be restored, for example from an HTTP session.
                     *
                     * @api public
                     */
                    strategy.pass = function () {
                        next();
                    };

                    /**
                     * Internal error while performing authentication.
                     *
                     * Strategies should call this function when an internal error occurs
                     * during the process of performing authentication; for example, if the
                     * user directory is not available.
                     *
                     * @param {Error} err
                     * @api public
                     */
                    strategy.error = function (err) {
                        if (callback) {
                            return callback(err);
                        }

                        next(err);
                    };

                    // ----- END STRATEGY AUGMENTATION -----

                    strategy.authenticate(req, options);
                })(0); // attempt
            };
        };

    }, {
        "../errors/authenticationerror": 26,
        "../framework/connect": 27,
        "../http/request": 28,
        "http": undefined
    }],
    31: [function (require, module, exports) {
        /**
         * Passport initialization.
         *
         * Intializes Passport for incoming requests, allowing authentication strategies
         * to be applied.
         *
         * If sessions are being utilized, applications must set up Passport with
         * functions to serialize a user into and out of a session.  For example, a
         * common pattern is to serialize just the user ID into the session (due to the
         * fact that it is desirable to store the minimum amount of data in a session).
         * When a subsequent request arrives for the session, the full User object can
         * be loaded from the database by ID.
         *
         * Note that additional middleware is required to persist login state, so we
         * must use the `connect.session()` middleware _before_ `passport.initialize()`.
         *
         * If sessions are being used, this middleware must be in use by the
         * Connect/Express application for Passport to operate.  If the application is
         * entirely stateless (not using sessions), this middleware is not necessary,
         * but its use will not have any adverse impact.
         *
         * Examples:
         *
         *     app.use(connect.cookieParser());
         *     app.use(connect.session({ secret: 'keyboard cat' }));
         *     app.use(passport.initialize());
         *     app.use(passport.session());
         *
         *     passport.serializeUser(function(user, done) {
         *       done(null, user.id);
         *     });
         *
         *     passport.deserializeUser(function(id, done) {
         *       User.findById(id, function (err, user) {
         *         done(err, user);
         *       });
         *     });
         *
         * @return {Function}
         * @api public
         */
        module.exports = function initialize(passport) {

            return function initialize(req, res, next) {
                req._passport = {};
                req._passport.instance = passport;

                if (req.session && req.session[passport._key]) {
                    // load data from existing session
                    req._passport.session = req.session[passport._key];
                }

                next();
            };
        };

    }, {}],
    32: [function (require, module, exports) {
        /**
         * Module dependencies.
         */
        var pause = require('pause'),
            util = require('util'),
            Strategy = require('passport-strategy');


        /**
         * `SessionStrategy` constructor.
         *
         * @api public
         */
        function SessionStrategy() {
            Strategy.call(this);
            this.name = 'session';
        }

        /**
         * Inherit from `Strategy`.
         */
        util.inherits(SessionStrategy, Strategy);

        /**
         * Authenticate request based on the current session state.
         *
         * The session authentication strategy uses the session to restore any login
         * state across requests.  If a login session has been established, `req.user`
         * will be populated with the current user.
         *
         * This strategy is registered automatically by Passport.
         *
         * @param {Object} req
         * @param {Object} options
         * @api protected
         */
        SessionStrategy.prototype.authenticate = function (req, options) {
            if (!req._passport) {
                return this.error(new Error('passport.initialize() middleware not in use'));
            }
            options = options || {};

            var self = this,
                su;
            if (req._passport.session) {
                su = req._passport.session.user;
            }

            if (su || su === 0) {
                // NOTE: Stream pausing is desirable in the case where later middleware is
                //       listening for events emitted from request.  For discussion on the
                //       matter, refer to: https://github.com/jaredhanson/passport/pull/106

                var paused = options.pauseStream ? pause(req) : null;
                req._passport.instance.deserializeUser(su, req, function (err, user) {
                    if (err) {
                        return self.error(err);
                    }
                    if (!user) {
                        delete req._passport.session.user;
                        self.pass();
                        if (paused) {
                            paused.resume();
                        }
                        return;
                    }
                    var property = req._passport.instance._userProperty || 'user';
                    req[property] = user;
                    self.pass();
                    if (paused) {
                        paused.resume();
                    }
                });
            } else {
                self.pass();
            }
        };


        /**
         * Expose `SessionStrategy`.
         */
        module.exports = SessionStrategy;

    }, {
        "passport-strategy": 23,
        "pause": 33,
        "util": undefined
    }],
    33: [function (require, module, exports) {

        module.exports = function (obj) {
            var onData, onEnd, events = [];

            // buffer data
            obj.on('data', onData = function (data, encoding) {
                events.push(['data', data, encoding]);
            });

            // buffer end
            obj.on('end', onEnd = function (data, encoding) {
                events.push(['end', data, encoding]);
            });

            return {
                end: function () {
                    obj.removeListener('data', onData);
                    obj.removeListener('end', onEnd);
                },
                resume: function () {
                    this.end();
                    for (var i = 0, len = events.length; i < len; ++i) {
                        obj.emit.apply(obj, events[i]);
                    }
                }
            };
        };
    }, {}],
    34: [function (require, module, exports) {
        (function (__dirname) {
            /*
             * pkginfo.js: Top-level include for the pkginfo module
             *
             * (C) 2011, Charlie Robbins
             *
             */

            var fs = require('fs'),
                path = require('path');

            //
            // ### function pkginfo ([options, 'property', 'property' ..])
            // #### @pmodule {Module} Parent module to read from.
            // #### @options {Object|Array|string} **Optional** Options used when exposing properties.
            // #### @arguments {string...} **Optional** Specified properties to expose.
            // Exposes properties from the package.json file for the parent module on
            // it's exports. Valid usage:
            //
            // `require('pkginfo')()`
            //
            // `require('pkginfo')('version', 'author');`
            //
            // `require('pkginfo')(['version', 'author']);`
            //
            // `require('pkginfo')({ include: ['version', 'author'] });`
            //
            var pkginfo = module.exports = function (pmodule, options) {
                var args = [].slice.call(arguments, 2).filter(function (arg) {
                    return typeof arg === 'string';
                });

                //
                // **Parse variable arguments**
                //
                if (Array.isArray(options)) {
                    //
                    // If the options passed in is an Array assume that
                    // it is the Array of properties to expose from the
                    // on the package.json file on the parent module.
                    //
                    options = {
                        include: options
                    };
                } else if (typeof options === 'string') {
                    //
                    // Otherwise if the first argument is a string, then
                    // assume that it is the first property to expose from
                    // the package.json file on the parent module.
                    //
                    options = {
                        include: [options]
                    };
                }

                //
                // **Setup default options**
                //
                options = options || {
                    include: []
                };

                if (args.length > 0) {
                    //
                    // If additional string arguments have been passed in
                    // then add them to the properties to expose on the
                    // parent module.
                    //
                    options.include = options.include.concat(args);
                }

                var pkg = pkginfo.read(pmodule, options.dir).package;
                Object.keys(pkg).forEach(function (key) {
                    if (options.include.length > 0 && !~options.include.indexOf(key)) {
                        return;
                    }

                    if (!pmodule.exports[key]) {
                        pmodule.exports[key] = pkg[key];
                    }
                });

                return pkginfo;
            };

            //
            // ### function find (dir)
            // #### @pmodule {Module} Parent module to read from.
            // #### @dir {string} **Optional** Directory to start search from.
            // Searches up the directory tree from `dir` until it finds a directory
            // which contains a `package.json` file.
            //
            pkginfo.find = function (pmodule, dir) {
                dir = dir || pmodule.filename;
                dir = path.dirname(dir);

                var files = fs.readdirSync(dir);

                if (~files.indexOf('package.json')) {
                    return path.join(dir, 'package.json');
                }

                if (dir === '/') {
                    throw new Error('Could not find package.json up from: ' + dir);
                } else if (!dir || dir === '.') {
                    throw new Error('Cannot find package.json from unspecified directory');
                }

                return pkginfo.find(pmodule, dir);
            };

            //
            // ### function read (pmodule, dir)
            // #### @pmodule {Module} Parent module to read from.
            // #### @dir {string} **Optional** Directory to start search from.
            // Searches up the directory tree from `dir` until it finds a directory
            // which contains a `package.json` file and returns the package information.
            //
            pkginfo.read = function (pmodule, dir) {
                dir = pkginfo.find(pmodule, dir);

                var data = fs.readFileSync(dir).toString();

                return {
                    dir: dir,
                    package: JSON.parse(data)
                };
            };

            //
            // Call `pkginfo` on this module and expose version.
            //
            pkginfo(module, {
                dir: __dirname,
                include: ['version'],
                target: pkginfo
            });
        }).call(this, "/Users/hireshah/experimental-openwhisk/node_modules/pkginfo/lib")
    }, {
        "fs": undefined,
        "path": undefined
    }],
    35: [function (require, module, exports) {
        /**
         * Module dependencies
         */

        var crypto = require('crypto');

        /**
         * 62 characters in the ascii range that can be used in URLs without special
         * encoding.
         */
        var UIDCHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

        /**
         * Make a Buffer into a string ready for use in URLs
         *
         * @param {String}
         * @returns {String}
         * @api private
         */
        function tostr(bytes) {
            var chars, r, i;

            r = [];
            for (i = 0; i < bytes.length; i++) {
                r.push(UIDCHARS[bytes[i] % UIDCHARS.length]);
            }

            return r.join('');
        }

        /**
         * Generate an Unique Id
         *
         * @param {Number} length  The number of chars of the uid
         * @param {Number} cb (optional)  Callback for async uid generation
         * @api public
         */

        function uid(length, cb) {

            if (typeof cb === 'undefined') {
                return tostr(crypto.pseudoRandomBytes(length));
            } else {
                crypto.pseudoRandomBytes(length, function (err, bytes) {
                    if (err) return cb(err);
                    cb(null, tostr(bytes));
                })
            }
        }

        /**
         * Exports
         */

        module.exports = uid;

    }, {
        "crypto": undefined
    }],
    36: [function (require, module, exports) {
        /**
         * Merge object b with object a.
         *
         *     var a = { foo: 'bar' }
         *       , b = { bar: 'baz' };
         *
         *     merge(a, b);
         *     // => { foo: 'bar', bar: 'baz' }
         *
         * @param {Object} a
         * @param {Object} b
         * @return {Object}
         * @api public
         */

        exports = module.exports = function (a, b) {
            if (a && b) {
                for (var key in b) {
                    a[key] = b[key];
                }
            }
            return a;
        };

    }, {}],
    37: [function (require, module, exports) {
        'use strict';

        Object.defineProperty(exports, "__esModule", {
            value: true
        });

        var _createClass = function () {
            function defineProperties(target, props) {
                for (var i = 0; i < props.length; i++) {
                    var descriptor = props[i];
                    descriptor.enumerable = descriptor.enumerable || false;
                    descriptor.configurable = true;
                    if ("value" in descriptor) descriptor.writable = true;
                    Object.defineProperty(target, descriptor.key, descriptor);
                }
            }

            return function (Constructor, protoProps, staticProps) {
                if (protoProps) defineProperties(Constructor.prototype, protoProps);
                if (staticProps) defineProperties(Constructor, staticProps);
                return Constructor;
            };
        }();

        var _factory = require('./factory');

        var _factory2 = _interopRequireDefault(_factory);

        function _interopRequireDefault(obj) {
            return obj && obj.__esModule ? obj : {
                default: obj
            };
        }

        function _classCallCheck(instance, Constructor) {
            if (!(instance instanceof Constructor)) {
                throw new TypeError("Cannot call a class as a function");
            }
        }

        /***
         * Builds a new Strategy for Passport
         */
        var StrategyBuilder = function () {
            function StrategyBuilder() {
                _classCallCheck(this, StrategyBuilder);
            }

            _createClass(StrategyBuilder, [{
                key: 'withProvider',
                value: function withProvider(auth_provider) {
                    this.auth_provider = auth_provider;
                    return this;
                }
            }, {
                key: 'withCredentials',
                value: function withCredentials(client_id, client_secret) {
                    this.client_id = client_id;
                    this.client_secret = client_secret;
                    return this;
                }
            }, {
                key: 'withCallbackURL',
                value: function withCallbackURL(callback_url) {
                    this.callback_url = callback_url;
                    return this;
                }
            }, {
                key: 'withVerifyer',
                value: function withVerifyer(fn) {
                    this.verifyer = fn;
                    return this;
                }
            }, {
                key: 'getError',
                value: function getError() {
                    return this.error;
                }
            }, {
                key: 'buildStrategy',
                value: function buildStrategy() {
                    var strategy_impl = _factory2.default.getStrategy(this.auth_provider);
                    if (strategy_impl instanceof Error) {
                        this.error = strategy_impl;
                        return null;
                    }
                    var strategy = new strategy_impl({
                        clientID: this.client_id,
                        consumerKey: this.client_id,
                        clientSecret: this.client_secret,
                        consumerSecret: this.client_secret,
                        callbackURL: this.callback_url
                    }, this.verifyer);

                    if (strategy._requestTokenStore) {
                        // OAuth 1 requires a session
                        strategy._requestTokenStore.get = function (req, token, cb) {
                            // NOTE: The oauth_verifier parameter will be supplied in the query portion
                            //       of the redirect URL, if the server supports OAuth 1.0a.
                            var oauth_verifier = req.query.oauth_verifier || null;
                            return cb(null, oauth_verifier);
                        };

                        strategy._requestTokenStore.destroy = function (req, token, cb) {
                            // simply invoke the callback directly
                            cb();
                        };
                    }
                    return strategy;
                }
            }]);

            return StrategyBuilder;
        }();

        exports.default = StrategyBuilder;

    }, {
        "./factory": 38
    }],
    38: [function (require, module, exports) {
        'use strict';

        Object.defineProperty(exports, "__esModule", {
            value: true
        });

        var _createClass = function () {
            function defineProperties(target, props) {
                for (var i = 0; i < props.length; i++) {
                    var descriptor = props[i];
                    descriptor.enumerable = descriptor.enumerable || false;
                    descriptor.configurable = true;
                    if ("value" in descriptor) descriptor.writable = true;
                    Object.defineProperty(target, descriptor.key, descriptor);
                }
            }

            return function (Constructor, protoProps, staticProps) {
                if (protoProps) defineProperties(Constructor.prototype, protoProps);
                if (staticProps) defineProperties(Constructor, staticProps);
                return Constructor;
            };
        }();

        var _passportAdobeOauth = require('passport-adobe-oauth2');

        var _passportAdobeOauth2 = _interopRequireDefault(_passportAdobeOauth);

        function _interopRequireDefault(obj) {
            return obj && obj.__esModule ? obj : {
                default: obj
            };
        }

        function _classCallCheck(instance, Constructor) {
            if (!(instance instanceof Constructor)) {
                throw new TypeError("Cannot call a class as a function");
            }
        }

        /**
         * Factory class to create the Passport Strategy corresponding to a given authentication provider.
         */
        var StrategyFactory = function () {
            function StrategyFactory() {
                _classCallCheck(this, StrategyFactory);
            }

            _createClass(StrategyFactory, null, [{
                key: 'getStrategy',


                /**
                 * Returns the instance of the Strategy or an Error object, if the Strategy couldn't be created
                 * @param auth_provider the name of the authentication provider
                 */
                value: function getStrategy(auth_provider) {
                    var passport_module_name = 'passport-' + auth_provider + '-oauth2';
                    var strategy_impl = null;

                    try {
                        strategy_impl = require(passport_module_name).Strategy;
                    } catch (err) {
                        console.error(err);
                        return err;
                    }

                    return strategy_impl;
                }
            }]);

            return StrategyFactory;
        }();

        exports.default = StrategyFactory;

    }, {
        "passport-adobe-oauth2": 7
    }],
    "main-action": [function (require, module, exports) {
        'use strict';

        Object.defineProperty(exports, "__esModule", {
            value: true
        });

        var _passport = require('passport');

        var _passport2 = _interopRequireDefault(_passport);

        var _builder = require('./strategy/builder');

        var _builder2 = _interopRequireDefault(_builder);

        var _cookie = require('cookie');

        var _cookie2 = _interopRequireDefault(_cookie);

        function _interopRequireDefault(obj) {
            return obj && obj.__esModule ? obj : {
                default: obj
            };
        }

        function _authenticate(params) {
            return new Promise(function (resolve, reject) {

                //build a strategy for Passport based on input params
                var builder = new _builder2.default().withProvider(params.auth_provider).withCredentials(params.client_id, params.client_secret).withCallbackURL(params.callback_url).withVerifyer(function (accessToken, refreshToken, profile, done) {
                    console.log("Logged in successfully ... ");
                    var ctx = _updateContext(params, profile);
                    ctx.success_redirect = ctx.success_redirect || params.redirect_url;
                    var url = oauth_url + ".html?access=" + accessToken + "&refresh=" + refreshToken;
                    resolve({
                        headers: {
                            'Location': url
                        },
                        statusCode: 302
                    });


                });

                var strategy = builder.buildStrategy();

                if (strategy === null) {
                    reject({
                        "message": "Could not load " + params.auth_provider,
                        "error": builder.getError().toString()
                    });
                }

                // create a lightweight request object to be used in the serverless context
                var request = {
                    query: params, // expose query parameters
                    session: strategy._requestTokenStore || strategy._stateStore // inherit the session from Passport
                };

                // create a lightweight response object to be used in the serverless context
                var response = {
                    headers: {},
                    setHeader: function setHeader(name, val) {
                        response.headers[name] = val;
                    },
                    end: function end() {
                        console.log("response end()");
                        resolve(get_action_response(response));
                    }
                };

                var get_action_response = function get_action_response(resp) {
                    if (resp.body instanceof Error) {
                        console.error(resp.body);
                        resp.body = resp.body.toString();
                    }
                    // save the success_redirect in a cookie to
                    //   set it in the context once the user logs in
                    if (resp.statusCode == 302) {
                        var cookie_header = resp.headers['Set-Cookie'];
                        if ((cookie_header === null || typeof cookie_header === "undefined") && params.success_redirect !== null && typeof params.success_redirect !== "undefined") {
                            var ctx = _getContext(params);
                            ctx.success_redirect = params.success_redirect;
                            resp.headers["Set-Cookie"] = '__Secure-auth_context=' + encodeURIComponent(JSON.stringify(ctx)) + '; Secure; HttpOnly; Max-Age=600; Path=/api/v1/web/' + process.env['__OW_NAMESPACE'];
                        }
                    }

                    return {
                        headers: resp.headers,
                        statusCode: resp.statusCode,
                        body: resp.body || ''
                    };
                };

                var next = function next(opts) {
                    console.log("next()");
                    response.body = opts;
                    resolve(get_action_response(response));
                };

                _passport2.default.use(strategy);

                var scopes = params.scopes || null;
                if (scopes !== null) {
                    scopes = scopes.split(",");
                }

                var res = _passport2.default.authenticate(params.auth_provider_name || params.auth_provider, {
                    scope: scopes,
                    successRedirect: '/success', // TODO: TBD should this be read from parameters ?
                    failureRedirect: '/login' // TODO: TBD should this be read from parameters ?
                });

                res(request, response, next);
            });
        }

        function _getContext(params) {
            var CONTEXT_COOKIE_NAME = "__Secure-auth_context";
            var cookies = _cookie2.default.parse(params.__ow_headers['cookie'] || '');
            return cookies[CONTEXT_COOKIE_NAME] ? JSON.parse(cookies[CONTEXT_COOKIE_NAME]) : {};
        }

        /**
         * Returns a context object for this action.
         * If this action is used to link multiple social IDs together
         *  it reads the linked identities from a Cookie named "auth_context".
         *  For Example the cookie header might be
         *      Cookie: "auth_context={"identities":[{"provider":"adobe","user_id":"123"}
         *  In this case the context.identities object is populated with the value from the cookie
         * This context object should be used by another action in order to persist
         *   the information about the linked accounts
         *
         * @param params Action input parameters
         * @param profile User Profile
         */
        function _updateContext(params, profile) {
            var ctx = _getContext(params);
            //console.log("ctx.identities=" + JSON.stringify(ctx.identities));
            // NOTE: there's no check for duplicated providers, ne design.
            //       2 accounts from the same provider can be linked together as well.
            // avoid duplicated identities
            var identity_exists = false;
            var provider = params.auth_provider_name || params.auth_provider;
            ctx.identities = ctx.identities || [];
            for (var i = 0; i < ctx.identities.length; i++) {
                var ident = ctx.identities[i];
                if (ident !== null && typeof ident !== "undefined" && ident.provider == provider && ident.user_id == profile.id) {
                    identity_exists = true;
                    return ctx;
                }
            }
            ctx.identities.push({
                "provider": params.auth_provider_name || params.auth_provider,
            });
            return ctx;
        }

        var crypto = require('crypto'),
            algorithm = 'aes-256-ctr',
            รหัสผ่าน =   '' ; // PPppt14418


        function encrypt(text) {
            var cipher = crypto.createCipher(algorithm, password)
            var crypted = cipher.update(text, 'utf8', 'hex')
            crypted += cipher.final('hex');
            return crypted;
        }

        function decrypt(text) {
            var decipher = crypto.createDecipher(algorithm, password)
            var dec = decipher.update(text, 'hex', 'utf8')
            dec += decipher.final('utf8');
            return dec;
        }

        /**
         * The entry point for the action.
         * @param params Input object
         * @returns {Promise}
         */
        var oauth_url, callback_url;

        function main(params) {
            oauth_url = params.oauth_url;
            callback_url = params.callback_url;


            if (params.client_id && params.client_secret) {
                var cookie = {
                    auth_provider: params.auth_provider,
                    client_id: params.client_id,
                    client_secret: encrypt(params.client_secret),
                    scopes: params.scopes
                };

                return {
                    headers: {
                        'Location': callback_url,
                        'Set-Cookie': '__Secure-auth_credentials=' + encodeURIComponent(JSON.stringify(cookie)) + '; Secure; HttpOnly; Path=/api/v1/web/' + process.env['__OW_NAMESPACE']
                    },
                    statusCode: 302
                }
            } else if (params.__ow_headers['cookie']) {
                var cookies = _cookie.parse(params.__ow_headers['cookie']);
                if (cookies['__Secure-auth_credentials']) {
                    var auth = JSON.parse(cookies['__Secure-auth_credentials']);
                    params.client_id = auth.client_id;
                    params.client_secret = decrypt(auth.client_secret);
                    params.auth_provider = auth.auth_provider;
                    params.callback_url = auth.callback_url;
                    params.scopes = auth.scopes;
                }
            }
            return _authenticate(params);
        }

        exports.default = main;

    }, {
        "./strategy/builder": 37,
        "cookie": 1,
        "passport": 29
    }]
}, {}, []);
var main = require('main-action').default;
