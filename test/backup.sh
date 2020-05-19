# mysql backup script
mysql_dump -uroot -p8u7iwgfYGf --all-databases > /media/backup/backup.sql
# this script is probably world-readable and probably the system root user has the same password as the mysql root 
# lol