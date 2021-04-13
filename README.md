## About Project

This project is a JWT secure API.
The API have 1 test route:

Get data Route

```bash
http://{{server}}/api/data
```

## Install providers

```bash
composer install
```

```bash
cp .env.example .env
```

```bash
php artisan key:generate
```

Installing a dependencies

```bash
composer require tymon/jwt-auth:dev-develop --prefer-source
```

Add "providers" at "config/app.php" 

```bash
Tymon\JWTAuth\Providers\LaravelServiceProvider::class,
```

Add "Aliases" at "config/app.php" 

```bash
'JWTAuth' => Tymon\JWTAuth\Facades\JWTAuth::class, 
'JWTFactory' => Tymon\JWTAuth\Facades\JWTFactory::class,
```

Execute on console

```bash
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```

if ok return a Token

```bash
php artisan jwt:secret
```
## Implementation

Go to "User" Model on "app/User.php" and Add:

```php
<?php

    namespace App;

    use Illuminate\Notifications\Notifiable;
    use Illuminate\Foundation\Auth\User as Authenticatable;

    //Añadimos la clase JWTSubject 
    use Tymon\JWTAuth\Contracts\JWTSubject;

    //Añadimos la implementación de JWT en nuestro modelo
    class User extends Authenticatable implements JWTSubject
    {
        use Notifiable;

        /**
         * The attributes that are mass assignable.
         *
         * @var array
         */
        protected $fillable = [
            'name', 'email', 'password',
        ];

        /**
         * The attributes that should be hidden for arrays.
         *
         * @var array
         */
        protected $hidden = [
            'password', 'remember_token',
        ];

        /*
            Añadiremos estos dos métodos
        */
        public function getJWTIdentifier()
        {
            return $this->getKey();
        }
        public function getJWTCustomClaims()
        {
            return [];
        }
    }
```

Add a new column on Database

```bash
php artisan migrate
```

Create a controller

```bash
php artisan make:controller UserController --resource
```

Edit UserController.php Controller

```php
<?php   
namespace App\Http\Controllers;

    use App\User;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Hash;
    use Illuminate\Support\Facades\Validator;
    use JWTAuth;
    use Tymon\JWTAuth\Exceptions\JWTException;

class UserController extends Controller
{
    public function authenticate(Request $request)
    {
        $credentials = $request->only('email', 'password');
        try {
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'invalid_credentials'], 400);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'could_not_create_token'], 500);
        }
        return response()->json(compact('token'));
    }
    public function getAuthenticatedUser()
    {
        try {
            if (!$user = JWTAuth::parseToken()->authenticate()) {
                    return response()->json(['user_not_found'], 404);
            }
            } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
                    return response()->json(['token_expired'], $e->getStatusCode());
            } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
                    return response()->json(['token_invalid'], $e->getStatusCode());
            } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {
                    return response()->json(['token_absent'], $e->getStatusCode());
            }
            return response()->json(compact('user'));
    }
}
```

If you need register a new user on API, adding at controller UserController.php

```bash
public function register(Request $request)
        {
                $validator = Validator::make($request->all(), [
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'password' => 'required|string|min:6|confirmed',
            ]);

            if($validator->fails()){
                    return response()->json($validator->errors()->toJson(), 400);
            }

            $user = User::create([
                'name' => $request->get('name'),
                'email' => $request->get('email'),
                'password' => Hash::make($request->get('password')),
            ]);

            $token = JWTAuth::fromUser($user);

            return response()->json(compact('user','token'),201);
        }
```

Create a Middleware

```bash
php artisan make:middleware JwtMiddleware
```

Add at the Middleware

```php
<?php

namespace App\Http\Middleware;

use Closure;
use JWTAuth;
use Exception;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;

class JwtMiddleware extends BaseMiddleware
{

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (Exception $e) {
            if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenInvalidException){
                return response()->json(['status' => 'Token is Invalid']);
            }else if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenExpiredException){
                return response()->json(['status' => 'Token is Expired']);
            }else{
                return response()->json(['status' => 'Authorization Token not found']);
            }
        }
        return $next($request);
    }
}
```

Go to "app/http/Kernel.php" and added at Middleware

```php
protected $routeMiddleware = [
        ...
        'jwt.verify' => \App\Http\Middleware\JwtMiddleware::class,
        ...
];
```

Create a group for the secure routes 

```php
 Route::group(['middleware' => ['jwt.verify']], function() {
       /*Add here the router on protected with JWT*/
 });
```

If you have a error "TypeError: Tymon\JWTAuth\JWT::fromUser(): Argument #1 ($user) must be of type Tymon\JWTAuth\Contracts\JWTSubject, App\User given," please check if you put code line "class User extends Authenticatable implements JWTSubject" on User.php 


## License
[MIT](https://choosealicense.com/licenses/mit/)
