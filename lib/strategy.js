/**
 * Module dependencies.
 */
var util = require('util'),
OAuth2Strategy = require('passport-oauth2').Strategy,
InternalOAuthError = require('passport-oauth2').InternalOAuthError,
crypto= require('crypto'),
querystring= require('querystring'),
https= require('https'),
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
  options.profileURL = options.profileURL || 'https://social.yahooapis.com/v1/user/:xoauthYahooGuid/profile?format=json';

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

  // NOTE: The module oauth (0.9.5), which is a dependency, automatically adds
  //       a 'type=web_server' parameter to the query portion of the URL.
  //       This appears to be an artifact from an earlier draft of OAuth 2.0
  //       (draft 22, as of the time of this writing).  This parameter is not
  //       necessary, but its presence does not appear to cause any issues.

  OAuth2Strategy.prototype.authenticate.call(this, req, options);
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

  request.get(request_options, function(err, response, body) {
    if(err) {
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }
    if (response.statusCode !== 200) {
      return done(new InternalOAuthError('Failed to fetch user profile', body));
    }
    try{
      var json = body.profile;
      json['id'] = json.guid;

      var profile = {
        provider: 'yahoo',
        id: json.id,
        displayName: [json.givenName || '', json.familyName || ''].join(' '),
        name: {
          familyName: json.familyName || '',
          givenName: json.givenName || ''
        },
        emails: [{
          value: (json.emails && json.emails[0].handle) || '',
          type: (json.emails && json.emails[0].type) || ''
        }],
        photos: [{
          value: (json.image && json.image.imageUrl) || ''
        }],
        _raw: body,
        _json: body
      };

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
