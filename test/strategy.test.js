var assert = require('assert');
var nock = require('nock');
var YahooStrategy = require('../lib/strategy');

const profileBody = JSON.stringify({
  sub: "JEF4XR2CT55JPVEBVD7ZVT6A3A",
  name: "Jasmine Smith",
  given_name: "Jasmine",
  family_name: "Smith",
  locale: "en-US",
  email: "yqa_functest_15572415322065371@yahoo.com",
  email_verified: true,
  birthdate: "1972",
  profile_images: {
     image32: "https://ct.yimg.com/cy/1768/39361574426_98028a_32sq.jpg",
     image64: "https://ct.yimg.com/cy/1768/39361574426_98028a_64sq.jpg",
     image128: "https://ct.yimg.com/cy/1768/39361574426_98028a_128sq.jpg",
     image192: "https://ct.yimg.com/cy/1768/39361574426_98028a_192sq.jpg"
  },
  preferred_username: "yqa_functest_15572415322065371@yahoo.com",
  phone_number: "+18663395023",
  nickname: "Jasmine",
  picture: "https://ct.yimg.com/cy/1768/39361574426_98028a_192sq.jpg"
});

describe('passport-yahoo strategy', function() {

  it('should build a yahoo strategy', function() {
    const strategy = new YahooStrategy({
      clientID: 'ABC123',
      clientSecret: 'secret'
    },
    function() {});

    assert.equal(strategy.name, 'yahoo');
  });

  describe('strategy when loading user profile', function() {
    before(function() {
      this.strategy = new YahooStrategy({
        clientID: 'ABC123',
        clientSecret: 'secret'
      },
      function() {});

      nock('https://api.login.yahoo.com')
        .get('/openid/v1/userinfo')
        .reply(200, profileBody);
    });

    describe('when told to load user profile', function() {
      before(function(done) {
        var _this = this;
        this.strategy.userProfile('token', function (err, profile) {
          _this.err = err;
          _this.profile = profile;
          done();
        });
      })

      it('should not error', function() {
        assert(this.err === null);
      })

      it('should load profile', function() {
        assert.equal(this.profile.provider, 'yahoo');
        assert.equal(this.profile.id, 'JEF4XR2CT55JPVEBVD7ZVT6A3A');
        assert.equal(this.profile.displayName, 'Jasmine Smith');
        assert.equal(this.profile.name.familyName, 'Smith');
        assert.equal(this.profile.name.givenName, 'Jasmine');
      })

      it('should set raw property', function() {
        assert(typeof this.profile._raw === 'string');
      })

      it('should set json property', function() {
        assert(this.profile._json);
      })
    })

  });


  describe('strategy when loading user profile and encountering an error', function() {
    before(function(){
      this.strategy = new YahooStrategy({
        clientID: 'ABC123',
        clientSecret: 'secret'
      },
      function() {});

      nock('https://api.login.yahoo.com')
        .get('/openid/v1/userinfo')
        .reply(401, 'NO');
    });

    describe('when told to load user profile', function() {
      before(function(done) {
        var _this = this;
        this.strategy.userProfile('token', function (err, profile) {
          _this.err = err;
          _this.profile = profile;
          done();
        });
      })

      it('should error', function() {
        assert(this.err !== null);
      });

      it('should wrap error in InternalOAuthError', function() {
        assert.equal(this.err.constructor.name, 'InternalOAuthError');
      });

      it('should not load profile', function() {
        assert(this.profile === undefined);
      });
    });
  });
});
