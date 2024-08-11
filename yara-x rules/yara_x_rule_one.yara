rule ExampleRule
{
    strings
        $my_text_string = potato
    condition
        $my_text_string 
}