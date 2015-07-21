'use strict';

var user = module.parent.require('./user'),
  meta = module.parent.require('./meta'),
  db = module.parent.require('../src/database'),
  passport = module.parent.require('passport'),
  passportWechat = require('passport-weixin').Strategy,
  fs = module.parent.require('fs'),
  path = module.parent.require('path'),
  nconf = module.parent.require('nconf'),
  async = module.parent.require('async');

var constants = module.parent.require('../plugin_configs/sso_wechat_constants');

var Wechat = {};

Wechat.getStrategy = function(strategies, callback) {
  passport.use(new passportWechat({
    clientID: constants.key,
    clientSecret: constants.secret,
    requireState: false,
    callbackURL: nconf.get('url') + '/auth/wechat/callback'
  }, function(accessToken, refreshToken, profile, done) {
    Wechat.login(profile.id, profile.displayName, function(err, user) {
      if (err) {
        return done(err);
      }
      done(null, user);
    });
  }));

  strategies.push({
    name: 'weixin',
    url: '/auth/wechat',
    callbackURL: '/auth/wechat/callback',
    icon: 'fa-weixin',
    scope: ''
  });

  callback(null, strategies);
};

Wechat.login = function(wxid, handle, callback) {
  Wechat.getUidByWechatId(wxid, function(err, uid) {
    if (err) {
      return callback(err);
    }

    if (uid !== null) {
      // Existing User
      callback(null, {
        uid: uid
      });
    } else {
      // New User
      user.create({
        username: handle
      }, function(err, uid) {
        if (err) {
          return callback(err);
        }

        // Save wechat-specific information to the user
        user.setUserField(uid, 'wxid', wxid);
        db.setObjectField('wxid:uid', wxid, uid);

        callback(null, {
          uid: uid
        });
      });
    }
  });
};

Wechat.getUidByWechatId = function(wxid, callback) {
  db.getObjectField('wxid:uid', wxid, function(err, uid) {
    if (err) {
      return callback(err);
    }
    callback(null, uid);
  });
};

Wechat.deleteUserData = function(uid, callback) {
  async.waterfall([
    async.apply(user.getUserField, uid, 'wxid'),
    function(oAuthIdToDelete, next) {
      db.deleteObjectField('wxid:uid', oAuthIdToDelete, next);
    }
  ], function(err) {
    if (err) {
      winston.error('[sso-wechat] Could not remove OAuthId data for uid ' + uid + '. Error: ' + err);
      return callback(err);
    }
    callback(null, uid);
  });
};

module.exports = Wechat;