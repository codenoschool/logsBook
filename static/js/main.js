$(document).ready(function(){
    console.log('I am ready.');
    // get current URL path and assign 'active' class
    var pathname = window.location.pathname;
    $('.navbar-nav > li > a[href="'+pathname+'"]').parent().addClass('active');
});