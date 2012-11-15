
function get_type(thing){
    if(thing===null)return "[object Null]"; // special case
    return Object.prototype.toString.call(thing);
}


$(document).ready(function() {
	// Add Mustache templates from <script id="" type="text/html"> elements of the page
	$.Mustache.addFromDom();

	$('form#netquery').submit(function(e) {
		e.preventDefault();
		netquery($("form#netquery #query").val());
	});

});

netquery_cache = {}

function netquery(string) {
	if (getURLParameter('query') != string) {
		history.pushState(null, null, "?query=" + encodeURIComponent(string));
	}
	searchType = false;

	if (string === null || string === "" || string == "null") {
		$('#netquery_output').html("");
		$('form#netquery input#query').val("");
		return;
	}

	// Reset results area
	$('form#netquery input#query').val(string);
	$('#netquery_output').html("Loading results ...");

	regex_is_ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;

	if (regex_is_ip.exec(string) !== null) {
		searchType = "ip";
	} else {
		searchType = "dns";
	}
	request = $.ajax({ url: "/" + searchType + "/" + encodeURIComponent(string), dataType: 'json'});
	request.success(function(data) {
		$('#netquery_output').mustache('query-' + searchType, data, { method: 'html' });
		embed($('#netquery_output'));
	});
	request.error(function(data) {
		$('#netquery_output').html("There was an ERROR.");
	});
}

window.addEventListener("popstate", function(e) {
	if (getURLParameter('query') !== null) {
		netquery(getURLParameter('query'));
	}
});

function getURLParameter(name) {
	return decodeURI((RegExp(name + '=' + '(.+?)(&|$)').exec(location.search)||[,null])[1]);
}

function embed(obj) {
	regex_is_ip = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;
	result = obj.html().replace(regex_is_ip, function(match, contents, offset, s) {
		return "<a href='#' onclick=\"netquery('" + match + "'); return false;\">" + match + "</a>";
	});
	obj.html(result);
}