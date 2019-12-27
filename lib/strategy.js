/**
 * Module dependencies.
 */
var util = require('util'),
  OAuth2Strategy = require('passport-oauth2').Strategy,
  InternalOAuthError = require('passport-oauth2').InternalOAuthError,
  crypto= require('crypto'),
  querystring= require('querystring'),
  https= require('https'),
  utils = require('./utils'),
  http= require('http'),
  url= require('url')
  request = require('request');


/**
* `Strategy` constructor.
*
* The Yahoo authentication strategy authenticates requests by delegating to
* Yahoo using the OAuth protocol.
*
* Applications must supply a `verify` callback which accepts a `token`,
* `tokenSecret` and service-specific `profile`, and then calls the `done`
* callback supplying a `user`, which should be set to `false` if the
* credentials are not valid.  If an exception occured, `err` should be set.
*
* Options:
*   - `consumerKey`     identifies client to Yahoo
*   - `consumerSecret`  secret used to establish ownership of the consumer key
*   - `callbackURL`     URL to which Yahoo will redirect the user after obtaining authorization
*
* Examples:
*
*     passport.use(new YahooStrategy({
*         consumerKey: '123-456-789',
*         consumerSecret: 'shhh-its-a-secret'
*         callbackURL: 'https://www.example.net/auth/yahoo/callback'
*       },
*       function(token, tokenSecret, profile, done) {
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
  //https://api.login.yahoo.com/oauth2/request_auth
  options = options || {};

  options.authorizationURL = options.authorizationURL || 'https://api.login.yahoo.com/oauth2/request_auth';
  options.tokenURL = options.tokenURL || 'https://api.login.yahoo.com/oauth2/get_token';
  options.profileURL = options.profileURL || 'https://api.login.yahoo.com/openid/v1/userinfo';

  OAuth2Strategy.call(this, options, verify);

  this._options = options;
  this.name = 'yahoo';
}

/**
* Inherit from `OAuthStrategy`.
*/
util.inherits(Strategy, OAuth2Strategy);


/**
* Override authenticate:
* inspired from post: http://yahoodevelopers.tumblr.com/post/105969451213/implementing-yahoo-oauth2-authentication
*
*/
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
    return this.fail();
  }

  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
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
      callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }

  var meta = {
    authorizationURL: this._oauth2._authorizeUrl,
    tokenURL: this._oauth2._accessTokenUrl,
    clientID: this._oauth2._clientId
  }

  if (req.query && req.query.code) {
    function loaded(err, ok, state) {
      if (err) { return self.error(err); }
      if (!ok) {
        return self.fail(state, 403);
      }

      var code = req.query.code;

      var params = self.tokenParams(options);
      params.grant_type = 'authorization_code';
      if (callbackURL) { params.redirect_uri = callbackURL; }

      self._oauth2.getOAuthAccessToken(code, params,
        function(err, accessToken, refreshToken, params) {
          if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }

          self._loadUserProfile(accessToken, params, function(err, profile) {
            if (err) { return self.error(err); }

            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }

              info = info || {};
              if (state) { info.state = state; }
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
    if (callbackURL) { params.redirect_uri = callbackURL; }
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
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
        if (err) { return self.error(err); }

        if (state) { params.state = state; }
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
}


/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
Strategy.prototype._loadUserProfile = function(accessToken, params, done) {
  var self = this;

  function loadIt() {
    return self.userProfile(accessToken, params, done);
  }
  function skipIt() {
    return done(null);
  }

  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) { return loadIt(); }
    return skipIt();
  }
};

/**
* Retrieve user profile from Yahoo.
* inpired from post: http://yahoodevelopers.tumblr.com/post/105969451213/implementing-yahoo-oauth2-authentication
* other code from : passport-yahoo-token repo
* This function constructs a normalized profile, with the following properties:
*
*   - `id`
*   - `displayName`
*
* @param {String} token
* @param {String} tokenSecret
* @param {Object} params
* @param {Function} done
* @api protected
*/
Strategy.prototype.userProfile = function (accessToken, params, done) {
  this._oauth2._useAuthorizationHeaderForGET = true;
  var request_options = {
    url: this._options.profileURL.replace(':xoauthYahooGuid', params.xoauth_yahoo_guid),
    headers: {
      Authorization: this._oauth2.buildAuthHeader(accessToken)
    },
    rejectUnauthorized: false,
    json: true
  };

  request.get(request_options, function(err, response, json) {
    if(err) {
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }
    if (response.statusCode !== 200) {
      return done(new InternalOAuthError('Failed to fetch user profile', json));
    }
    try{

      var profile = { provider: 'yahoo' };
      profile.id = json.sub;
      profile.displayName = json.name;
      profile.name = { familyName: json.family_name,
                       givenName: json.given_name };

      profile._raw = json;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}


/**
* Expose `Strategy`.
*/
module.exports = Strategy;
