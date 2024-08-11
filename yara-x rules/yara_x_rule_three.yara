rule ExampleRule
{
    strings
        $my_text_string = tomato
    condition
        $my_text_string 
}