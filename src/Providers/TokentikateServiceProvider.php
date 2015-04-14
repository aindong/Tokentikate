<?php
namespace Aindong\Tokentikate\Providers;

use Aindong\Tokentikate\Helpers;
use Illuminate\Support\ServiceProvider;
use Aindong\Tokentikate\TokentikateClass;

class TokentikateServiceProvider extends ServiceProvider {
    public function register()
    {
        $this->app['tokentikate'] = $this->app->share(function($app) {
            return new TokentikateClass(new Helpers);
        });
    }
}