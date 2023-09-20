python3 .\setup.py bdist_wheel

Write-Host "Copying files to iriswebapp_worker and iriswebapp_app..."
docker cp .\dist\iris_threatfox_module-1.2.0-py3-none-any.whl iriswebapp_worker:/iriswebapp/dependencies/iris_threatfox_module-py3-none-any.whl
docker cp .\dist\iris_threatfox_module-1.2.0-py3-none-any.whl iriswebapp_app:/iriswebapp/dependencies/iris_threatfox_module-py3-none-any.whl

Write-Host "Installing the modules..."
docker exec -it iriswebapp_worker /bin/bash -c "pip3 install /iriswebapp/dependencies/iris_threatfox_module-py3-none-any.whl --force-reinstall"
docker exec -it iriswebapp_app /bin/bash -c "pip3 install /iriswebapp/dependencies/iris_threatfox_module-py3-none-any.whl --force-reinstall"

Write-Host "Restarting hosts..."
docker restart iriswebapp_worker
docker restart iriswebapp_app

Write-Host "Complete!"