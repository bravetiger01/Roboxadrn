function geoFindMe() {

  const options = {
    enableHighAccuracy: true,
    timeout: 5000,
    maximumAge: 0,
  };



  function success(position) {
    const latitude = position.coords.latitude;
    const longitude = position.coords.longitude;

    console.log("Latitude:", latitude, "Longitude:", longitude); // Debugging
    // Send location to Flask backend
    fetch('/update_location', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ latitude: latitude, longitude: longitude })
    })
      .then(response => response.json())
      .then(data => console.log("Server Response:", data))
      .catch(error => console.error("Error:", error));
  }

  function error() {
    console.error("Unable to retrieve location.");
}

if (!navigator.geolocation) {
    console.error("Geolocation is not supported by this browser.");
} else {
    console.log("Locating...");
    navigator.geolocation.getCurrentPosition(success, error, options);
}
}

geoFindMe();