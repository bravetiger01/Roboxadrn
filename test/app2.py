from flask import Flask, request, jsonify

app = Flask(__name__)

def is_inside_geofence(lat, lng, geofence_points):
    """Checks if a point is inside a geofence."""
    min_lat = min(p[0] for p in geofence_points)
    max_lat = max(p[0] for p in geofence_points)
    min_lng = min(p[1] for p in geofence_points)
    max_lng = max(p[1] for p in geofence_points)

    if not (min_lat <= lat <= max_lat and min_lng <= lng <= max_lng):
        return False

    inside = False
    for i in range(len(geofence_points)):
        j = (i + 1) % len(geofence_points)
        lat_i, lng_i = geofence_points[i]
        lat_j, lng_j = geofence_points[j]

        if (lng_i < lng and lng_j >= lng) or (lng_j < lng and lng_i >= lng):
            if lat_i + (lat_j - lat_i) * (lng - lng_i) / (lng_j - lng_i) < lat:
                inside = not inside

    return inside

@app.route('/check_location', methods=['GET'])  # Changed to GET
def check_location():
    try:
        lat = float(request.args.get('latitude'))
        lng = float(request.args.get('longitude'))

        # Geofence points (hardcoded in the code) -  REPLACE WITH YOUR POINTS
        geofence_points = [
                            (15.4869153, 74.9306135),  
                            (15.4783736, 74.9271729),  
                            (15.4832603, 74.9465056),  
                            (15.4920739, 74.9438794),]

        if is_inside_geofence(lat, lng, geofence_points):
            result = {'status': 'inside', 'message': 'Location is inside the geofence.'}
        else:
            result = {'status': 'outside', 'message': 'Location is outside the geofence.'}

        return jsonify(result), 200

    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid input. Please provide latitude and longitude as numbers.'}), 400
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)