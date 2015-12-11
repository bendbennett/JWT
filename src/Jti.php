<?php

namespace Bendbennett\JWT;

use Illuminate\Database\Eloquent\Model;

class Jti extends Model
{
    protected $fillable = ['jti', 'exp'];
}