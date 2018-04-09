<?php
namespace app\index\controller;

class Index
{
    public function index()
    {
        echo input("get","code");
    }
}
