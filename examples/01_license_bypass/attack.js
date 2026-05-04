// marrow: flip licenseValid() to always return true.
// Run via: marrow.exe agent <pid> eval "$(cat attack.js)"
var App = Java.use('App');
App.licenseValid.setReturn(1);   // 1 = true for boolean
Marrow.log('license bypass: licenseValid() now always returns true');

// Output changes from "trial mode" to "PREMIUM FEATURE UNLOCKED"
// without recompiling the app, without a license file, without restart.
