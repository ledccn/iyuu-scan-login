<?php

namespace Iyuu\ScanLogin\Framework\ThinkPHP;

use RuntimeException;
use think\console\Input;
use think\console\input\Argument;
use think\console\input\Option;
use think\console\Output;
use Throwable;

/**
 * 构建命令
 */
class Command extends \think\console\Command
{
    /**
     * 指令配置
     * @return void
     */
    protected function configure()
    {
        $this->setName('make:model:trait')
            ->addArgument('connection', Argument::REQUIRED, "数据库连接名称")
            ->addArgument('table', Argument::OPTIONAL, "完整的数据表名称")
            ->addOption('all', null, Option::VALUE_NONE, '批量生成所有数据表的注释')
            ->addOption('m', null, Option::VALUE_NONE, '是否同时生成模型')
            ->setDescription('批量生成thinkPHP项目的表注释');
    }

    /**
     * 执行指令
     * @param Input $input
     * @param Output $output
     * @return void
     */
    protected function execute(Input $input, Output $output)
    {
        try {
            // 接收参数
            $connection = $input->getArgument('connection');
            $table = $input->getArgument('table');
            $isAll = $input->hasOption('all');
            $isGenerateModel = $input->hasOption('m');

            // 读取配置
            $connections = config('database.connections');
            $config = $connections[$connection] ?? [];
            if (empty($connection) || empty($config)) {
                throw new RuntimeException('数据库连接配置信息为空');
            }
            if (empty($table) && empty($isAll)) {
                throw new RuntimeException('数据表名称为空');
            }

            if ($isAll) {
                // 批量
                foreach (Util::getTables($connection) as $table) {
                    $this->generate($connection, $table, $config, $isGenerateModel);
                }
            } else {
                // 单个
                $this->generate($connection, $table, $config, $isGenerateModel);
            }

            $output->writeln('命令make:trait 已生成模型注释');
        } catch (Throwable $throwable) {
            $output->writeln((string)$throwable);
        }
    }

    /**
     * 获取模型或特性的命名空间
     * @return string
     */
    protected function getNamespace(): string
    {
        return 'app\model';
    }

    /**
     * 生成数据表的字段注释
     * @param string $connection 数据库连接名称
     * @param string $table 完整的数据表名称
     * @param array $config 数据库配置
     * @param bool $isGenerateModel 是否同时生成模型
     * @return void
     */
    protected function generate(string $connection, string $table, array $config, bool $isGenerateModel = false): void
    {
        $class = Util::nameToClass($table);
        $file = app_path('model') . "$class.php";

        $path = pathinfo($file, PATHINFO_DIRNAME);
        if (!is_dir($path)) {
            mkdir($path, 0777, true);
        }

        $namespace = $this->getNamespace();
        $table_val = 'null';
        $pk = 'id';
        $properties = '';
        try {
            $connect = Util::getConnect($connection);
            $prefix = $config['prefix'] ?? '';
            $database = $config['database'];
            if ($connect->query("show tables like '{$prefix}{$table}'")) {
                $table = "{$prefix}{$table}";
                $table_val = "'$table'";
            } else if ($connect->query("show tables like '{$prefix}{$table}s'")) {
                $table = "{$prefix}{$table}s";
                $table_val = "'$table'";
            }
            $tableComment = $connect->query('SELECT table_comment FROM information_schema.`TABLES` WHERE table_schema = ? AND table_name = ?', [$database, $table]);
            if (!empty($tableComment)) {
                $comments = $tableComment[0]['table_comment'] ?? $tableComment[0]['TABLE_COMMENT'];
                $properties .= " * {$table} {$comments}" . PHP_EOL;
            }
            foreach ($connect->query("select COLUMN_NAME,DATA_TYPE,COLUMN_KEY,COLUMN_COMMENT from INFORMATION_SCHEMA.COLUMNS where table_name = '$table' and table_schema = '$database' ORDER BY ordinal_position") as $item) {
                if ($item['COLUMN_KEY'] === 'PRI') {
                    $pk = $item['COLUMN_NAME'];
                    $item['COLUMN_COMMENT'] .= "(主键)";
                }
                $type = $this->getType($item['DATA_TYPE']);
                $properties .= " * @property $type \${$item['COLUMN_NAME']} {$item['COLUMN_COMMENT']}\n";
            }
        } catch (Throwable $e) {
        }
        $properties = rtrim($properties) ?: ' *';
        $model_content = <<<EOF
<?php

namespace $namespace;

use think\\Model;

/**
$properties
 */
class $class extends Model
{
    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected \$table = $table_val;

    /**
     * The primary key associated with the table.
     *
     * @var string
     */
    protected \$pk = '$pk';
}

EOF;
        if ($isGenerateModel) {
            file_put_contents($file, $model_content);
        }

        $trait_content = <<<EOF
<?php

namespace $namespace;

/**
$properties
 */
trait Has$class
{
}

EOF;
        file_put_contents(dirname($file) . "/Has{$class}.php", $trait_content);
    }

    /**
     * @param string $type
     * @return string
     */
    protected function getType(string $type): string
    {
        if (strpos($type, 'int') !== false) {
            return 'integer';
        }
        switch ($type) {
            case 'varchar':
            case 'string':
            case 'text':
            case 'date':
            case 'time':
            case 'guid':
            case 'datetimetz':
            case 'datetime':
            case 'decimal':
            case 'enum':
                return 'string';
            case 'boolean':
                return 'integer';
            case 'float':
                return 'float';
            default:
                return 'mixed';
        }
    }
}
