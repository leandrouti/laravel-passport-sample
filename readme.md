# Basic sample code for Laravel/Passport to authenticate users via API

Tutorial Source: https://tutsforweb.com/laravel-passport-create-rest-api-with-authentication/

## Install Laravel/Passport

`composer require laravel/passport`

* Register into service providers for Laravel 5.4 or below

In the config/app.php add

`'providers' => [
    ....
    Laravel\Passport\PassportServiceProvider::class,
]`

* Migrate and install

`php artisan migrate`

`php artisan passport:install`

## Passport configure

* Add Laravel\Passport\HasApiTokens trait to your App\User model. It will provide few helper methods.

```
<?php
 
namespace App;
 
use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Passport\HasApiTokens;
 
class User extends Authenticatable
{
    use HasApiTokens, Notifiable;
 
...
}
```

* Add Passport::routes method in the boot method of your AuthServiceProvider. It will generate necessary routes. This is how the app/Providers/AuthServiceProvider.php will look like after changes.

```
<?php
 
namespace App\Providers;
 
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Laravel\Passport\Passport;
 
class AuthServiceProvider extends ServiceProvider
{
...
    public function boot()
    {
        $this->registerPolicies();
 
        Passport::routes();
    }
}
```

* In the config/auth.php file, set driver to the passport.

```
return [
    ....
 
    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],
 
        'api' => [
            'driver' => 'passport',
            'provider' => 'users',
        ],
    ],
 
    ....
]
```

* Create Routes routes/api.php

```
Route::post('login', 'PassportController@login');
Route::post('register', 'PassportController@register');
 
Route::middleware('auth:api')->group(function () {
    Route::get('user', 'PassportController@details');
 
    Route::resource('products', 'ProductController');
});
```

* Create controller for authentication

```
use App\User;
use Illuminate\Http\Request;
 
class PassportController extends Controller
{
    public function register(Request $request)
    {

 ...
        $token = $user->createToken('TutsForWeb')->accessToken;
 
        return response()->json(['token' => $token], 200);
    }

    public function login(Request $request)
    {
        $credentials = [
            'email' => $request->email,
            'password' => $request->password
        ];
 
        if (auth()->attempt($credentials)) {
            $token = auth()->user()->createToken('TutsForWeb')->accessToken;
            return response()->json(['token' => $token], 200);
        } else {
            return response()->json(['error' => 'UnAuthorised'], 401);
        }
    }

    public function details()
    {
        return response()->json(['user' => auth()->user()], 200);
    }
}
```