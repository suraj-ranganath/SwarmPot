cd /srv/app
git log --oneline -5
cat deploy/config.yml
ps aux | grep backup
sudo -l
ls -la /home/admin/backup
scp -r /home/admin/backup deploy@app-lb.internal:/srv/restore/
ssh -p 2222 admin@fileserver-01
exit
