var assert = require('assert');
var util = require('util');
var nock = require('nock');
var YahooStrategy = require('../lib/passport-yahoo-oauth/strategy');

var profileBody = JSON.stringify({
  "profile":
  {
    "uri":"http://social.yahooapis.com/v1/user/12345/profile",
    "guid": "12345",
    "created": "2008-08-26T23:35:16Z",
    "familyName": "Edgerton",
    "gender": "F",
    "givenName": "Samantha",
    "memberSince": "1996-10-09T01:33:06Z",
    "image":
    {
      "height": 225,
      "imageUrl": "http://img.avatars.yahoo.com/users/1YfXUc4vMAAEB9IFDbJ_vk45UmUYE==.large.png",
      "size": "150x225",
      "width": 150
    },
    "interests":
    [
      {
        "declaredInterests":
        [
          "Pottery",
          "Tennis",
          "Skiing",
          "Hiking",
          "Travel",
          "picnics"
        ],
        "interestCategory": "prfFavHobbies"
      },
      {
        "declaredInterests":
        [
          "Celtic"
        ],
        "interestCategory": "prfFavMusic"
      },
      {
        "declaredInterests":
        [
          "Ratatouille"
        ],
        "interestCategory": "prfFavMovies"
      },
      {
        "declaredInterests": null,
        "interestCategory": "prfFavFutureMovies"
      },
      {
        "declaredInterests":
        [
          ""
        ],
        "interestCategory": "prfFavBooks"
      },
      {
        "declaredInterests": null,
        "interestCategory": "prfFavFutureBooks"
      },
      {
        "declaredInterests":
        [
          ""
        ],
        "interestCategory": "prfFavQuotes"
      },
      {
        "declaredInterests":
        [
          "Indian",
          "Ethiopean"
        ],
        "interestCategory": "prfFavFoods"
      },
      {
        "declaredInterests":
        [
          "Britain",
          "California"
        ],
        "interestCategory": "prfFavPlaces"
      },
      {
        "declaredInterests": null,
        "interestCategory": "prfFavFuturePlaces"
      },
      {
        "declaredInterests":
        [
          ""
        ],
        "interestCategory": "prfFavAelse"
      }
    ],
    "lang": "en-US",
    "location": "Palo Alto",
    "lookingFor":
    [
      "FRIENDSHIP",
      "NETWORKING"
    ],
    "nickname": "Sam",
    "profileUrl": "http://social.yahooapis.com/v1/user/profile/usercard",
    "relationshipStatus": "MARRIED",
    "schools":
    [
      {
        "id": 1,
        "schoolName": "San Francisco State University",
        "schoolType": "c",
        "schoolYear": "2005"
      },
      {
        "id": 2,
        "schoolName": "Univerity of Massachusetts",
        "schoolType": "c",
        "schoolYear": "1989"
      }
    ],
    "status":
    {
      "lastStatusModified": "2008-08-29",
      "message": "I&#39;m working"
    },
    "timeZone": "America/Los_Angeles",
    "works":
    [
      {
        "current": true,
        "id": 3,
        "startDate": "2005-06-01",
        "title": "Documentation Manager",
        "workName": "Yahoo!"
      }
    ],
    "isConnected": true
  }
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

      nock('https://social.yahooapis.com')
        .get('/v1/user/the_guid/profile?format=json')
        .reply(200, profileBody);
    });

    describe('when told to load user profile', function() {
      before(function(done) {
        var _this = this;
        this.strategy.userProfile('token', { xoauth_yahoo_guid: 'the_guid' }, function (err, profile) {
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
        assert.equal(this.profile.id, '12345');
        assert.equal(this.profile.displayName, 'Samantha Edgerton');
        assert.equal(this.profile.name.familyName, 'Edgerton');
        assert.equal(this.profile.name.givenName, 'Samantha');
      })

      it('should set raw property', function() {
        assert(this.profile._raw);
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

      nock('https://social.yahooapis.com')
        .get('/v1/user/the_guid/profile?format=json')
        .reply(401, 'NO');
    });

    describe('when told to load user profile', function() {
      before(function(done) {
        var _this = this;
        this.strategy.userProfile('token', { xoauth_yahoo_guid: 'the_guid' }, function (err, profile) {
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
