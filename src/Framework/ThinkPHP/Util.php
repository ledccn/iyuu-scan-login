<?php

namespace Iyuu\ScanLogin\Framework\ThinkPHP;

use InvalidArgumentException;
use RuntimeException;
use think\db\ConnectionInterface;
use think\facade\Db;

/**
 * 工具类
 */
class Util
{
    /**
     * 创建/切换数据库连接查询
     * @param string $name 连接配置标识
     * @return ConnectionInterface
     */
    public static function getConnect(string $name): ConnectionInterface
    {
        return Db::connect($name);
    }

    /**
     * 获取所有数据表名称
     * @param string $connection 数据库连接名称
     * @param string $order 排序：asc升序、desc降序
     * @return array
     */
    public static function getTables(string $connection, string $order = 'asc'): array
    {
        $connections = config('database.connections');
        if (empty($connection) || empty($connections[$connection])) {
            throw new RuntimeException('数据库连接配置信息为空');
        }

        if (!in_array($order, ['asc', 'desc'])) {
            throw new InvalidArgumentException('错误的排序参数：asc升序、desc降序');
        }

        $config = $connections[$connection];
        $database = $config['database'];
        $field = 'TABLE_NAME';
        $results = static::getConnect($connection)->query("SELECT TABLE_NAME,TABLE_COMMENT,ENGINE,TABLE_ROWS,CREATE_TIME,UPDATE_TIME,TABLE_COLLATION FROM information_schema.`TABLES` WHERE TABLE_SCHEMA='$database' order by $field $order");
        if (empty($results)) {
            return [];
        }

        return array_column($results, $field);
    }

    /**
     * @param string $name
     * @return string
     */
    public static function nameToNamespace(string $name): string
    {
        $namespace = ucfirst($name);
        $namespace = preg_replace_callback(['/-([a-zA-Z])/', '/(\/[a-zA-Z])/'], function ($matches) {
            return strtoupper($matches[1]);
        }, $namespace);

        return str_replace('/', '\\', ucfirst($namespace));
    }

    /**
     * @param string $class
     * @return string
     */
    public static function classToName(string $class): string
    {
        $class = lcfirst($class);
        return preg_replace_callback(['/([A-Z])/'], function ($matches) {
            return '_' . strtolower($matches[1]);
        }, $class);
    }

    /**
     * @param string $class
     * @return string
     */
    public static function nameToClass(string $class): string
    {
        $class = preg_replace_callback(['/-([a-zA-Z])/', '/_([a-zA-Z])/'], function ($matches) {
            return strtoupper($matches[1]);
        }, $class);

        if (!($pos = strrpos($class, '/'))) {
            $class = ucfirst($class);
        } else {
            $path = substr($class, 0, $pos);
            $class = ucfirst(substr($class, $pos + 1));
            $class = "$path/$class";
        }
        return $class;
    }
}