# Keycloak

Valid for Keyckloak version 19.0.0 - 20.0.3 (later versions should be checked)
https://www.keycloak.org/docs/latest/server_admin/#rp-initiated-logout

```bash
composer require andreas-bochkov/laravel-socialiteprovier-keycloak
```

## Installation & Basic Usage

Please see the [Base Installation Guide](https://socialiteproviders.com/usage/), then follow the provider specific instructions below.

### Add configuration to `config/services.php`

```php
'keycloak' => [
  // Specify your keycloak client ID here
  'client_id' => env('KEYCLOAK_CLIENT_ID'),
  // Specify your keycloak client secret
  'client_secret' => env('KEYCLOAK_CLIENT_SECRET'),
  // Specify your app redirect URI
  'redirect' => env('KEYCLOAK_REDIRECT_URI'),
  // Specify your keycloak server URL here
  'base_url' => env('KEYCLOAK_BASE_URL'),
  // Specify your keycloak realm
  'realms' => env('KEYCLOAK_REALM'),
  // Specify your app post logout URI
  'post_logout_redirect_uri' => env('KEYCLOAK_POST_LOGOUT_REDIRECT_URI'),
  // Optional specify your keycloak backend URL, if differs from its base URL
  'backend_url' => env('KEYCLOAK_BACKEND_URL')
 ],
```

### Add provider event listener

Configure the package's listener to listen for `SocialiteWasCalled` events.

Add the event to your `listen[]` array in `app/Providers/EventServiceProvider`. See the [Base Installation Guide](https://socialiteproviders.com/usage/) for detailed instructions.

```php
protected $listen = [
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        // ... other providers
        \SocialiteProviders\Keycloak\KeycloakExtendSocialite::class.'@handle',
    ],
];
```

### Usage

You should now be able to use the provider like you would regularly use Socialite (assuming you have the facade installed):

```php
return Socialite::driver('keycloak')->redirect();
```

In the handle method the `id_token` should be saved to be able to logout later

```php
    $oauthUser = Socialite::driver('keycloak')->user();
    $user = User::updateOrCreate([
      'oauth_user_id'=>$oauthUser->id
    ], [
      'oauth_id_token'=>$oauthUser->accessTokenResponseBody['id_token']
    ]);
```

To logout of your app and Keycloak:
```php
public function logout() {
    $idTokenHint=Auth::user()->oauth_id_token;
    Auth::logout(); // Logout of your app
    return redirect(Socialite::driver('keycloak')->getLogoutUrl($idTokenHint)); // Redirect to Keycloak
}
```
