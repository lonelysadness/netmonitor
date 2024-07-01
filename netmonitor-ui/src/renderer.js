/* renderer.js */
document.addEventListener('DOMContentLoaded', () => {
  fetchConnections();
  setInterval(fetchConnections, 5000); // Fetch new connections every 5 seconds
});

function fetchConnections() {
  fetch('http://localhost:4000/connections')
    .then(response => response.json())
    .then(data => {
      console.log('Fetched connections:', data); // Log fetched data for debugging
      renderConnections(data);
    })
    .catch(error => console.error('Error fetching connections:', error));
}

function renderConnections(data) {
  const accordion = document.getElementById('connectionsAccordion');
  accordion.innerHTML = ''; // Clear existing connections

  Object.keys(data).forEach(group => {
    const connections = data[group];

    const accordionItem = document.createElement('div');
    accordionItem.className = 'accordion-item';

    const accordionHeader = document.createElement('div');
    accordionHeader.className = 'accordion-header';
    accordionHeader.innerHTML = `
      <div class="group-title">
        ${group}
      </div>
      <div class="group-actions">
        <button class="toggle-button" onclick="toggleGroup('${group}')">Toggle</button>
      </div>
    `;

    const accordionBody = document.createElement('div');
    accordionBody.className = 'accordion-body';

    connections.forEach(conn => {
      const connectionType = conn.Direction === 'Outgoing' ? 'Internet' : 'LAN';
      const destinationLabel = connectionType === 'Internet' ? conn.Domain : 'Peer-to-Peer';
      const countryCode = connectionType === 'Internet' ? conn.DestinationCountry.substring(0, 2).toUpperCase() : 'LAN';
      const directionArrow = conn.Direction === 'Outgoing' ? '→' : '←';

      const connectionRow = document.createElement('div');
      connectionRow.className = 'connection-row';
      connectionRow.innerHTML = `
        <div class="conn-details">
          <div class="conn-summary">
            <div class="left">
              <span class="conn-item domain-name">${destinationLabel}</span>
              <span class="conn-item">${countryCode}</span>
              <span class="conn-item">${conn.Process}</span>
              <span class="conn-item">${conn.DestinationIP} ${directionArrow}</span>
            </div>
            <div class="right">
              <button class="action-button" onclick="blockConnection('${conn.PID}')">Block</button>
            </div>
          </div>
          <div class="conn-extra">
            <div><strong>Source IP:</strong> ${conn.SourceIP}</div>
            <div><strong>Destination IP:</strong> ${conn.DestinationIP}</div>
            <div><strong>Protocol:</strong> ${conn.Protocol}</div>
            <div class="country flag-icon flag-icon-${conn.DestinationCountry.toLowerCase()}"></div>
            <div><strong>Process:</strong> ${conn.Process}</div>
            <div><strong>PID:</strong> ${conn.PID}</div>
            <div><strong>ASN:</strong> ${conn.ASN}</div>
            <div><strong>Org:</strong> ${conn.Org}</div>
            <div><strong>Domain:</strong> ${conn.Domain}</div>
            <div><strong>Start Time:</strong> ${conn.StartTime}</div>
            <div><strong>End Time:</strong> ${conn.EndTime}</div>
            <div><strong>Local Address:</strong> ${conn.LocalAddress}</div>
            <div><strong>Remote Address:</strong> ${conn.RemoteAddress}</div>
            <div><strong>Direction:</strong> ${conn.Direction === 'Outgoing' ? '↑ Outgoing' : '↓ Incoming'}</div>
            <div><strong>Encrypted:</strong> ${conn.Encrypted}</div>
            <div><strong>Tunnel:</strong> ${conn.Tunnel}</div>
          </div>
        </div>
      `;
      connectionRow.querySelector('.conn-summary').onclick = () => toggleDetails(connectionRow);
      accordionBody.appendChild(connectionRow);
    });

    accordionItem.appendChild(accordionHeader);
    accordionItem.appendChild(accordionBody);
    accordion.appendChild(accordionItem);
  });
}

function toggleGroup(group) {
  const groupElements = document.querySelectorAll(`.accordion-body`);
  groupElements.forEach(elem => {
    if (elem.previousElementSibling.querySelector('.group-title').innerText === group) {
      elem.style.display = elem.style.display === 'none' ? 'block' : 'none';
    }
  });
}

function toggleDetails(connectionRow) {
  const details = connectionRow.querySelector('.conn-extra');
  details.style.display = details.style.display === 'none' ? 'block' : 'none';
}

function blockConnection(connId) {
  console.log('Blocking connection with ID:', connId);
}

