const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');
const Profile = require('../models/Profile');

// SECURITY: OAuth 2.0 via Google - trusted identity provider
// Eliminates password-based attack surface for OAuth users
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      scope: ['profile', 'email'],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        if (!email) {
          return done(new Error('No email returned from Google'), null);
        }

        let user = await User.findOne({ email });

        if (user) {
          // SECURITY: Mark existing user as OAuth authenticated
          if (!user.oauthProvider) {
            user.oauthProvider = 'google';
            user.oauthId = profile.id;
            await user.save();
          }
          return done(null, user);
        }

        // SECURITY: Create new user from OAuth - no password needed
        // passwordHash set to null for OAuth-only accounts
        user = await User.create({
          email,
          passwordHash: null,
          oauthProvider: 'google',
          oauthId: profile.id,
          isActive: true,
          lastLogin: new Date(),
          // SECURITY: OAuth users skip password expiry (no password)
          passwordExpiry: null,
        });

        
        await Profile.create({
          userId: user._id,
          fullName: profile.displayName || email.split('@')[0],
          photoUrl: profile.photos?.[0]?.value || null,
        });

        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

module.exports = passport;