import os
import sys
import configparser
import argparse
import hashlib
from minio import Minio
from minio.error import S3Error

CONFIG_FILE = "s3_config.ini"


def calculate_md5(file_path):
    """计算文件的MD5哈希值"""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        print(f"计算MD5错误: {file_path} - {str(e)}")
        return None


def save_config(endpoint, access_key, secret_key, bucket, prefix):
    """保存配置到文件"""
    config = configparser.ConfigParser()
    config["S3"] = {
        "endpoint": endpoint,
        "access_key": access_key,
        "secret_key": secret_key,
        "bucket": bucket,
        "prefix": prefix if prefix else ""
    }
    with open(CONFIG_FILE, "w") as configfile:
        config.write(configfile)
    print(f"配置已保存到 {CONFIG_FILE}")


def load_config():
    """从文件加载配置"""
    if not os.path.exists(CONFIG_FILE):
        return None

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    s3_section = config["S3"]

    return {
        "endpoint": s3_section["endpoint"],
        "access_key": s3_section["access_key"],
        "secret_key": s3_section["secret_key"],
        "bucket": s3_section["bucket"],
        "prefix": s3_section.get("prefix", "")  # 处理旧版配置可能没有prefix的情况
    }


def interactive_setup():
    """交互式配置模式"""
    print("=" * 50)
    print("上传配置工具")
    print("=" * 50)
    endpoint = input("1. API 端点 (不要加前缀！！！不要加带存储桶名字的！！！'): ").strip()
    access_key = input("2. Access Key: ").strip()
    secret_key = input("3. Secret Key: ").strip()
    bucket = input("4. 存储桶名称: ").strip()

    # 询问是否要创建特定文件夹
    create_folder = input("\n是否要在云端创建特定文件夹保存文件? (y/n): ").strip().lower()
    prefix = ""
    if create_folder in ['y', 'yes']:
        folder_name = input("请输入文件夹名称: ").strip()
        # 规范化文件夹名称（移除首尾空格和斜杠）
        folder_name = folder_name.strip().strip("/")
        if folder_name:
            prefix = f"{folder_name}/"
            print(f"所有文件将上传到: {prefix}")
        else:
            print("未输入有效文件夹名称，将上传到存储桶根目录")
    else:
        print("文件将上传到存储桶根目录")

    save_config(endpoint, access_key, secret_key, bucket, prefix)
    print("\n配置完成! 使用 --update 参数执行上传")
    print("配置文件将储存在本地s3_config.ini")


def get_relative_path(file_path, base_dir):
    """获取文件相对于基目录的路径"""
    return os.path.relpath(file_path, base_dir).replace("\\", "/")


def find_files_to_upload(base_dir):
    """查找所有需要上传的文件"""
    files_to_upload = []
    self_name = os.path.basename(sys.argv[0])

    for root, _, files in os.walk(base_dir):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = get_relative_path(file_path, base_dir)

            # 排除配置文件和程序自身
            if relative_path == CONFIG_FILE:
                continue
            if relative_path.endswith(".exe") and relative_path.lower() == self_name.lower():
                continue

            files_to_upload.append((file_path, relative_path))

    return files_to_upload


def upload_files():
    """上传文件到S3存储桶，包括子目录"""
    print("正在加载配置...")
    config = load_config()
    if not config:
        print("错误: 未找到配置文件，请先运行直接启动程序来配置")
        sys.exit(1)

    print("正在连接服务器...")
    try:
        client = Minio(
            config["endpoint"],
            access_key=config["access_key"],
            secret_key=config["secret_key"],
            secure=True  # 使用HTTPS
        )
    except Exception as e:
        print(f"连接失败: {str(e)}")
        sys.exit(1)

    bucket_name = config["bucket"]
    prefix = config.get("prefix", "")

    # 验证存储桶是否存在
    try:
        if not client.bucket_exists(bucket_name):
            print(f"错误: 存储桶 '{bucket_name}' 不存在")
            print("好像这个存储桶不存在呢。。。（现在还不支持创建呢...）")
            sys.exit(1)
    except S3Error as err:
        print(f"存储桶验证错误: {str(err)}")
        print("真的有这个存储桶吗？")
        sys.exit(1)

    print(f"正在使用存储桶: {bucket_name}")
    if prefix:
        print(f"所有文件将上传到文件夹: {prefix}")

    print("正在扫描本地文件和目录...")
    base_dir = os.getcwd()
    files_to_upload = find_files_to_upload(base_dir)

    print(f"找到 {len(files_to_upload)} 个待处理文件(包括子目录)")
    print("正在检查云端重复文件...")

    uploaded = 0
    skipped = 0
    errors = 0

    for file_path, relative_path in files_to_upload:
        # 添加前缀到对象名称
        object_name = prefix + relative_path if prefix else relative_path

        print(f"\n处理文件: {relative_path}")
        if prefix:
            print(f"云端路径: {object_name}")

        # 计算本地文件MD5
        local_md5 = calculate_md5(file_path)
        if local_md5 is None:
            print("错误: 无法计算MD5，跳过此文件")
            errors += 1
            continue

        print(f"本地文件MD5: {local_md5}")

        try:
            # 获取远程对象信息
            obj_info = client.stat_object(bucket_name, object_name)
            remote_md5 = obj_info.etag.strip('"')
            print(f"云端文件MD5: {remote_md5}")

            if local_md5 == remote_md5:
                print("文件内容相同，跳过上传")
                skipped += 1
                continue
            else:
                print("文件内容不同，执行覆盖上传")
        except S3Error as err:
            if err.code == "NoSuchKey":
                print("云端不存在此文件，执行上传")
            else:
                print(f"检查错误: {str(err)}")
                errors += 1
                continue

        # 执行文件上传
        print(f"上传中: {relative_path} -> {bucket_name}/{object_name}")
        try:
            client.fput_object(
                bucket_name,
                object_name,
                file_path
            )
            print("上传成功!")
            uploaded += 1
        except Exception as e:
            print(f"上传失败: {str(e)}")
            errors += 1

    print("\n" + "=" * 50)
    print(f"上传完成! 总计: {len(files_to_upload)}")
    print(f"成功: {uploaded}, 跳过: {skipped}, 失败: {errors}")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(description="Minecraft服务器备份工具")
    parser.add_argument("--update", action="store_true", help="执行文件上传操作")
    args = parser.parse_args()

    if args.update:
        print("=" * 50)
        print("启动Minecraft服务器备份模式")
        print("=" * 50 + "\n")
        upload_files()
    else:
        interactive_setup()


if __name__ == "__main__":
    main()