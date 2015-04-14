<?php
namespace Aindong\Tokentikate\Facades;

use Illuminate\Support\Facades\Facade;

class Tokentikate extends Facade {
    protected static function getFacadeAccessor() {
        return 'tokentikate';
    }
}