Run ngrok to allow tunnelling from Mac.  Need to install ngrok first, run the command from the folder the ngrok exe is placed.
ngrok http http://localhost:5070

The 5070 is setup in launchSettings.json
After running the command use the url provided by ngrok to access the application from the internet.

Remember to update the test iOS application so the baseURL matches the new url.