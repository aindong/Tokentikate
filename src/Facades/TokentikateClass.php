<?php
namespace Aindong\Tokentikate\Facades;

use Illuminate\Support\Facades\Facade;

class TokentikateClass extends Facade {
    protected static function getFacadeAccessor() {
        return 'tokentikate';
    }
}