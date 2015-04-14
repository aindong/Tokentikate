<?php
namespace Aindong\Tokentikate\Providers;

use Illuminate\Support\ServiceProvider;
use Aindong\Tokentikate\Tokentikate;

class TokentikateServiceProvider extends ServiceProvider {
    public function register()
    {
        $this->app['tokentikate'] = $this->app->share(function($app) {
            return new Tokentikate;
        });
    }
}