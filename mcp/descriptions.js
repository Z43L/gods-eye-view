/**
 * Agent-facing descriptions for every GEV action. The argument schemas come
 * from `src/voice/actionSchemas.js` (single source of truth); this file only
 * carries the wording agents read.
 */

export const ACTION_DESCRIPTIONS = {
  fly_to_location:
    'Fly the camera to a place. Use query for any place name or address ("Eiffel Tower", "Tokyo"), locationId for a preset city, or latitude/longitude. viewMode close/overview or rangeM (meters) controls altitude. Set waitForArrival true to wait until the camera arrives.',
  select_nearest_aircraft:
    'Select the nearest aircraft to a place or coordinates, from the flights or military layer. The camera focuses on it.',
  adjust_camera_zoom:
    'Zoom the camera in or out by a little, medium, or lot.',
  zoom_to_globe: 'Zoom out to see the whole globe.',
  set_layer_visibility:
    'Show or hide a live data layer: flights, military, earthquakes, satellites, rocket-launches, traffic, cctv, radio, bikeshare, ais-live-vessels, local-datacenters, local-dams, telegeography-submarine-cables, local-firms, alpr-cameras.',
  show_data_layers_menu:
    'Open the data layers menu, optionally scrolled to a specific layer.',
  set_panel_open: 'Open or close a UI panel (data-panel, cctv-panel, radio-panel, scene-panel, control-panel, location-bar, pp-toggles, global-context-panel).',
  set_context_mode:
    'Set the global context mode: flights, space-missions, missions, contacts, or off.',
  control_cockpit:
    'Cockpit follow-cam: enter/exit, or step to the previous/next tracked aircraft. status reports the current state.',
  set_visual_style:
    'Change the globe visual style: normal, retro, surveillance, thermal, anime, noir, snow.',
  get_entity_context:
    'Get details about the currently selected entity, or entities in view (scope in_view, optional layerId filter, limit up to 12).',
  get_current_view_state:
    'Get the current camera and view state: position, target, range, heading.',
  set_hud: 'Show, hide, or restyle the HUD overlay (tactical, operator, minimal).',
  set_detection:
    'Configure the contacts detection overlay: enabled, density mode (sparse/balanced/dense).',
  set_map_stack:
    'Switch the basemap stack: photoreal, bing-aerial, bing-labels, esri-imagery, osm.',
  set_post_processing:
    'Tune post-processing: bloom and sharpen, each with enabled and intensityPct.',
  control_scene:
    'Cinematic scenes: list available scenes, play or stop one by sceneId, go next, or check status.',
  control_cctv:
    'Control CCTV cameras: enable/disable the layer, select a camera by query, hop next/prev/nearest, focus, coverage and viewshed analysis, autohop.',
  control_radio:
    'Control internet radio: play/pause/stop, next/previous station, volume, select a station by query, place, or country.',
  track_entity:
    'Start camera-tracking an entity (aircraft, vessel, satellite) by name query, optionally restricted to a layer.',
  stop_tracking: 'Stop tracking the currently tracked entity.',
  frame_overhead:
    'Frame an overhead view centered on flights, military, satellites, or vessels within radiusKm.',
  annotate_map:
    'Draw on the map: pins, highlights, areas, arrows, routes, labels. Each annotation takes a type plus targets/coordinates. Set flyTo to move the camera there, persist to keep them.',
  clear_annotations: 'Remove all map annotations.',
  move_camera:
    'Move the camera: orbit, pan, tilt, or rotate; direction left/right/up/down; speed slow/normal/fast; once or continuous. Use motion stop to end continuous motion.',
  fly_route: 'Fly a cinematic route by label, at slow/normal/fast speed.',
  analyst_query:
    'Query live data layers (flights, military, ais-live-vessels, local-firms, earthquakes) with a scope (view, region, radius, anywhere), filters (field/op/value), sorting, and a limit. Set followUp true to chain on the previous query.',
  next_iss_pass:
    'Compute the next visible ISS pass over a latitude/longitude, with an optional minimum elevation.',
};

export const UTILITY_DESCRIPTIONS = {
  gev_app_status:
    "Check whether the God's Eye View app is connected to the agent bridge, plus queue depth.",
  gev_wait_for_app:
    'Wait until the app connects to the agent bridge (for scripting: start the app first, then proceed).',
  gev_capture_screenshot:
    'Capture a JPEG screenshot of the current globe view, so you can see what the app shows.',
};

export const NETWORK_DESCRIPTIONS = {
  network_triangulate:
    'Passively triangulate a network identifier (IP, hostname, BSSID, SSID or ASN) across free public sources (ip-api, RIPEstat, PeeringDB, crt.sh, reverse DNS, WiGLE/OpenCelliD when tokens are set). Returns a fused dossier with position, honest confidence and per-source evidence, and stores it in the local SQLite network inventory. 100% passive: no scanning, no probing of third-party networks.',
  network_inventory_list:
    'List the networks stored in the local SQLite inventory (from past triangulations), most recently observed first. Each entry carries its fused position, confidence and source states.',
};

export const RECON_DESCRIPTIONS = {
  recon_fingerprint:
    'Actively inspect and fingerprint an exposed HTTP/HTTPS, TLS or RTSP endpoint (e.g. CCTV cameras, radio streams, IoT web servers). Gathers server banners, HTML titles, auth challenges, security headers (HSTS, CSP, CORS), and full TLS certificates (SANs, issuer, expiry), persisting the result in SQLite.',
  recon_traceroute:
    'Perform an active network traceroute probe towards a target IP or domain, measuring hop-by-hop RTT latencies, geolocating intermediate transit nodes, and storing the route in SQLite for 3D globe visualization.',
  recon_dns_lookup:
    'Perform active DNS reconnaissance on a domain or IP, querying all record types (A, AAAA, MX, TXT/SPF/DMARC, NS, SOA, CAA, PTR) and checking configuration policies, persisting findings in SQLite.',
  recon_inventory_query:
    'Query the persistent SQLite reconnaissance database for previously scanned targets, active fingerprints, network traces, and DNS records by query, tag, or target ID.',
};

