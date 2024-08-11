rule ExampleRule
{
    strings
        $my_text_string = fries
    condition
        $my_text_string 
}