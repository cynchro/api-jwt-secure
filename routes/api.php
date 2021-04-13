<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});

Route::post('auth/signin', 'UserController@authenticate');

Route::post('auth/signup', 'UserController@register');

Route::post('auth/registered', 'UserController@getAuthenticatedUser');

Route::get('all', 'DataController@test');

Route::get('admin', 'DataController@admin');

Route::get('user/all', 'UserController@all');

Route::group(['middleware' => ['jwt.verify']], function() {
    Route::get('data/', 'DataController@index');
});

