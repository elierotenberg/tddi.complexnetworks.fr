$(document).ready(function() {
    var loadees = ["udpping-input", "udpping-output", "udpping-source", "udpexplore-output", "udpexplore-source"];
    $.each(loadees, function(k, id) {
        $("#" + id).load("./" + id + ".html");
    });
});