<?php

namespace Iyuu\ScanLogin\Contracts;

/**
 * 驱动接口
 */
interface Driver
{
    /**
     * @return mixed
     */
    public function handle();
}
